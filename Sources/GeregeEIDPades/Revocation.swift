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

    /// Go `validate.OCSPCertIDMatches`: every SingleResponse for `cert`'s serial carries `issuer`'s CertID
    /// (issuerNameHash = H(issuer subject), issuerKeyHash = H(issuer subjectPublicKey); SHA-1/256/384/512) and there is
    /// at least one. `parse` selects by serial only, so a response for another issuer's certificate with the same
    /// serial (even from the same responder) must not count for this certificate.
    static func certIDMatches(_ der: [UInt8], cert: X509Cert, issuer: X509Cert) -> Bool {
        guard let top = try? DER.parse(der), top.tag == 0x30, let f = try? top.children(), f.count == 2,
              f[0].tag == 0x0A, f[0].contents == [0], let rb = try? f[1].expect(0xA0).child(0),
              let octets = try? rb.child(1).expect(0x04), let basic = try? DER.parse(octets.value),
              basic.tag == 0x30, var t = try? basic.child(0).children() else { return false }
        if t.first?.tag == 0xA0 { t.removeFirst() }             // version
        guard t.count >= 3, t[2].tag == 0x30, let singles = try? t[2].children() else { return false }
        let serial = DER.minimal(cert.serial)
        var found = false
        for single in singles {
            guard let cid = try? single.child(0).children(), cid.count == 4, cid[1].tag == 0x04, cid[2].tag == 0x04,
                  cid[3].tag == 0x02, let alg = try? cid[0].child(0).oid else { return false }
            guard cid[3].unsignedInteger == serial else { continue }
            guard [OID.sha1, OID.sha256, OID.sha384, OID.sha512].contains(alg),
                  let nameHash = Crypto.digest(alg, issuer.rawSubject), let keyHash = Crypto.digest(alg, issuer.publicKeyBits),
                  cid[1].contents == nameHash, cid[2].contents == keyHash else { return false }
            found = true
        }
        return found
    }
}

/// Freshness of revocation evidence — Go `validate.FreshAt` (README §7.2, golden validate/v4).
enum Revocation {
    /// thisUpdate may be at most this long before the check time when nextUpdate does not cover it.
    static let maxAge: TimeInterval = 24 * 3600
    /// Responder ↔ checker clock tolerance.
    static let clockSkew: TimeInterval = 5 * 60

    /// A response with thisUpdate/nextUpdate is "good" evidence at `at` (the check time — the timestamp time, else now):
    /// thisUpdate not after now + skew; nextUpdate (when present) not before at − skew; thisUpdate ≥ at − 24 h, or
    /// [thisUpdate, nextUpdate] covers `at`. Not applied to "revoked" (a revocation does not expire).
    static func freshAt(thisUpdate: Date, nextUpdate: Date?, at: Date, now: Date) -> Bool {
        if thisUpdate > now.addingTimeInterval(clockSkew) { return false }
        if let n = nextUpdate, n < at.addingTimeInterval(-clockSkew) { return false }
        if thisUpdate >= at.addingTimeInterval(-maxAge) { return true }
        return nextUpdate != nil && thisUpdate <= at
    }
}

/// A chain certificate is revoked by its issuer-signed OCSP response or CRL (Go `pades.ErrCertificateRevoked`).
struct CertificateRevoked: Error, CustomStringConvertible {
    let ref: String
    var description: String { "certificate revoked (" + ref + ")" }
}

enum CRL {
    struct Parsed {
        let rawIssuer: [UInt8]
        let authorityKeyId: [UInt8]
        let thisUpdate: Date
        let nextUpdate: Date?
        /// Revoked serials (unsigned magnitude, leading zeros removed).
        let revoked: [[UInt8]]
        let tbs: [UInt8]
        let sigAlg: String
        let signature: [UInt8]
    }

    /// CertificateList { tbsCertList, signatureAlgorithm, signature } (RFC 5280 §5.1).
    static func parse(_ der: [UInt8]) -> Parsed? {
        guard let top = try? DER.parse(der), top.tag == 0x30, top.raw.count == der.count,
              let f = try? top.children(), f.count == 3, f[0].tag == 0x30,
              let sigAlg = try? f[1].child(0).oid, f[2].tag == 0x03, f[2].value.first == 0,
              var t = try? f[0].children() else { return nil }
        if t.first?.tag == 0x02 { t.removeFirst() }               // version
        guard t.count >= 3, t[1].tag == 0x30, let thisUpdate = t[2].time else { return nil }
        var i = 3
        var next: Date?
        if i < t.count, t[i].tag == 0x17 || t[i].tag == 0x18 {
            guard let n = t[i].time else { return nil }
            next = n
            i += 1
        }
        var revoked: [[UInt8]] = []
        if i < t.count, t[i].tag == 0x30 {
            guard let entries = try? t[i].children() else { return nil }
            for e in entries {
                guard let s = try? e.child(0), s.tag == 0x02 else { return nil }
                revoked.append(s.unsignedInteger)
            }
            i += 1
        }
        var aki: [UInt8] = []
        if i < t.count, t[i].tag == 0xA0, let exts = try? t[i].child(0).children() {
            for ext in exts {
                guard let p = try? ext.children(), p.first?.oid == OID.authorityKeyId, let v = p.last, v.tag == 0x04,
                      let seq = try? DER.parse(v.value), let parts = try? seq.children() else { continue }
                if let kid = parts.first(where: { $0.tag == 0x80 }) { aki = kid.contents }
            }
        }
        return Parsed(rawIssuer: t[1].bytes, authorityKeyId: aki, thisUpdate: thisUpdate, nextUpdate: next,
                      revoked: revoked, tbs: f[0].bytes, sigAlg: sigAlg, signature: Array(f[2].value.dropFirst()))
    }

    /// Go `validate.CRLFor`: the CRL of `cert`'s issuer — CRL issuer = cert issuer = issuer subject (raw bytes), AKI
    /// (when both present) = the issuer's SKI, signed by the issuer (a CA allowed to sign CRLs).
    static func isFor(_ crl: Parsed, cert: X509Cert, issuer: X509Cert) -> Bool {
        guard crl.rawIssuer == cert.rawIssuer, crl.rawIssuer == issuer.rawSubject else { return false }
        if !crl.authorityKeyId.isEmpty, !issuer.subjectKeyId.isEmpty, crl.authorityKeyId != issuer.subjectKeyId { return false }
        return issuer.mayIssue(X509Cert.keyUsageCRLSign)
            && Crypto.verify(alg: crl.sigAlg, key: issuer, data: crl.tbs, signature: crl.signature)
    }

    /// Go `crlCovers`: `der` is a CRL of `c`'s issuer with a nextUpdate, fresh now (`Revocation.freshAt`), `c` not
    /// listed. Throws `CertificateRevoked` when `c` is listed in its issuer's CRL.
    static func covers(_ der: [UInt8], cert c: X509Cert, issuer: X509Cert, now: Date) throws -> Bool {
        guard let crl = parse(der), isFor(crl, cert: c, issuer: issuer) else { return false }
        if crl.revoked.contains(DER.minimal(c.serial)) { throw CertificateRevoked(ref: c.serialRef) }
        return crl.nextUpdate != nil && Revocation.freshAt(thisUpdate: crl.thisUpdate, nextUpdate: crl.nextUpdate, at: now, now: now)
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
