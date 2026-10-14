import Foundation

/// OCSP (RFC 6960) request/response and CRL (RFC 5280) — what the Go reference does with
/// golang.org/x/crypto/ocsp and crypto/x509 for the DSS.
enum OCSP {
    enum Status { case good, revoked, unknown }

    struct Response {
        let status: Status
        let thisUpdate: Date
        let nextUpdate: Date?
        /// First embedded certificate (delegated responder), if any.
        let certificate: X509Cert?
    }

    /// OCSPRequest with one SHA-1 CertID (Go `ocsp.CreateRequest(cert, issuer, {Hash: SHA1})`, byte-identical).
    static func request(cert: X509Cert, issuer: X509Cert) -> [UInt8] {
        let certID = DERW.seq(
            DERW.algID(OID.sha1, nullParams: true),
            DERW.octet(Crypto.sha1(issuer.rawSubject)),
            DERW.octet(Crypto.sha1(issuer.publicKeyBits)),
            DERW.tlv(0x02, cert.serial))
        return DERW.seq(DERW.seq(DERW.seq(DERW.seq(certID))))
    }

    /// Go `ocsp.ParseResponseForCert`: the single response for `cert`, signature checked against the embedded
    /// responder certificate (itself signed by `issuer`) or `issuer`.
    static func parse(_ der: [UInt8], cert: X509Cert, issuer: X509Cert) throws -> Response {
        let top = try DER.parse(der).expect(0x30)
        guard top.raw.count == der.count else { throw DERError("trailing data in OCSP response") }
        let f = try top.children()
        guard f.count == 2, f[0].tag == 0x0A, f[0].contents == [0] else { throw DERError("OCSP response status") }
        let rb = try f[1].expect(0xA0).child(0)
        guard try rb.child(0).oid == OID.ocspBasic else { throw DERError("bad OCSP response type") }
        let basic = try DER.parse(try rb.child(1).expect(0x04).value).expect(0x30)
        let b = try basic.children()
        guard b.count >= 3 else { throw DERError("BasicOCSPResponse shape") }
        let tbs = b[0]
        let sigAlg = try b[1].child(0).oid ?? ""
        let sigBits = try b[2].expect(0x03).contents
        guard sigBits.first == 0 else { throw DERError("OCSP signature bits") }
        let signature = Array(sigBits.dropFirst())
        var embedded: X509Cert?
        if b.count > 3, b[3].tag == 0xA0, let first = try b[3].child(0).children().first {
            embedded = try X509Cert(der: first.bytes)
        }
        if let rc = embedded {
            guard Crypto.verify(alg: sigAlg, key: rc, data: tbs.bytes, signature: signature) else {
                throw DERError("bad signature on embedded certificate")
            }
            guard Crypto.verify(alg: rc.sigAlgorithm, key: issuer, data: rc.tbs, signature: rc.signature) else {
                throw DERError("bad OCSP signature")
            }
        } else {
            guard Crypto.verify(alg: sigAlg, key: issuer, data: tbs.bytes, signature: signature) else {
                throw DERError("bad OCSP signature")
            }
        }
        var t = try tbs.children()
        if t.first?.tag == 0xA0 { t.removeFirst() }             // version
        guard t.count >= 3, t[0].tag == 0xA1 || t[0].tag == 0xA2 else { throw DERError("responder id") }
        let responses = try t[2].expect(0x30).children()
        guard !responses.isEmpty else { throw DERError("no responses") }
        for single in responses {
            let s = try single.children()
            guard s.count >= 3 else { continue }
            let cid = try s[0].children()
            guard cid.count == 4, cid[3].tag == 0x02, cid[3].unsignedInteger == DER.minimal(cert.serial) else { continue }
            guard [OID.sha1, OID.sha256, OID.sha384, OID.sha512].contains(try cid[0].child(0).oid ?? "") else {
                throw DERError("unsupported issuer hash algorithm")
            }
            let status: Status
            switch s[1].tag {
            case 0x80: status = .good
            case 0xA1: status = .revoked
            default: status = .unknown
            }
            guard let thisUpdate = s[2].time else { throw DERError("thisUpdate") }
            var next: Date?
            for e in s.dropFirst(3) {
                if e.tag == 0xA0 { next = try e.child(0).time }
                if e.tag == 0xA1 {
                    for ext in try e.child(0).children() {
                        let p = try ext.children()
                        if p.count == 3, p[1].tag == 0x01, p[1].value.first == 0xFF {
                            throw DERError("unsupported critical extension")
                        }
                    }
                }
            }
            return Response(status: status, thisUpdate: thisUpdate, nextUpdate: next, certificate: embedded)
        }
        throw DERError("no response matching the supplied certificate")
    }

    /// Signed by the issuer itself or by an issuer-certified id-kp-OCSPSigning responder (Go `responderOK`).
    static func responderOK(_ r: Response, issuer: X509Cert) -> Bool {
        guard let c = r.certificate, c != issuer else { return true }
        return c.extKeyUsage.contains(OID.kpOCSPSigning)
    }
}

enum CRL {
    /// Go `crlCovers`: `der` is a CRL of `c`'s issuer (signature checked), nextUpdate present and not past,
    /// `c` not listed.
    static func covers(_ der: [UInt8], cert c: X509Cert, issuer: X509Cert, now: Date) -> Bool {
        guard let top = try? DER.parse(der), top.tag == 0x30, top.raw.count == der.count,
              let f = try? top.children(), f.count == 3,
              let sigAlg = try? f[1].child(0).oid, f[2].tag == 0x03, f[2].value.first == 0,
              var t = try? f[0].children() else { return false }
        let tbs = f[0].bytes
        let signature = Array(f[2].value.dropFirst())
        if t.first?.tag == 0x02 { t.removeFirst() }               // version
        guard t.count >= 3, t[1].bytes == c.rawIssuer,
              Crypto.verify(alg: sigAlg, key: issuer, data: tbs, signature: signature) else { return false }
        guard t.count >= 4, let next = t[3].time, next >= now else { return false }
        if t.count >= 5, t[4].tag == 0x30, let revoked = try? t[4].children() {
            let serial = DER.minimal(c.serial)
            for entry in revoked {
                if let s = try? entry.child(0), s.tag == 0x02, s.unsignedInteger == serial { return false }
            }
        }
        return true
    }
}

extension DER {
    /// Unsigned magnitude of INTEGER contents (leading zeros removed) — for serial comparison.
    static func minimal(_ contents: [UInt8]) -> [UInt8] {
        var v = contents
        while v.count > 1, v[0] == 0 { v.removeFirst() }
        return v
    }
}
