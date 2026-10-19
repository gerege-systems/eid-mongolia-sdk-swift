import Foundation
import Security

/// RFC 3161 client — port of the Go reference `pades/tsa.go` (digitorus/timestamp request encoding, response
/// checks: nonce, imprint, token signature, TSA chain to the roots with a critical EKU {timeStamping}, genTime ±10 min).
enum TSA {
    static let defaultURL = "https://tsa.timeserver.mn/"
    static let maxSkew: TimeInterval = 10 * 60

    struct Token {
        /// TimeStampToken ContentInfo DER (goes into the CMS unsigned attribute).
        let raw: [UInt8]
        let genTime: Date
        /// Certificates carried in the token, in token order (they also go to the DSS).
        let certificates: [X509Cert]
    }

    /// TimeStampReq { version 1, messageImprint { sha256 (NULL params), hash }, nonce, certReq TRUE }.
    static func request(hash: [UInt8], nonce: [UInt8]) -> [UInt8] {
        DERW.seq(
            DERW.int(1),
            DERW.seq(DERW.algID(OID.sha256, nullParams: true), DERW.octet(hash)),
            DERW.uint(nonce),
            DERW.bool(true))
    }

    static func timestamp(_ f: Fetcher, url: String, signature: [UInt8], nonce: [UInt8], roots: [X509Cert],
                          intermediates: [X509Cert], now: Date) async throws -> Token {
        let sum = Crypto.sha256(signature)
        let body = try await f.fetch("POST", url, contentType: "application/timestamp-query",
                                     body: request(hash: sum, nonce: nonce))
        let parsed = try parse(body, expectedHash: sum, nonce: nonce)
        let tok = parsed.token
        let signer = try verifySignature(parsed)
        guard isTSASigningCert(signer) else { throw DERError("TSA cert EKU is not critical {timeStamping}") }
        guard chainsToRoot(signer, pool: tok.certificates + intermediates, roots: roots, at: tok.genTime) else {
            throw DERError("TSA certificate chain")
        }
        guard abs(now.timeIntervalSince(tok.genTime)) <= maxSkew else { throw DERError("TSA genTime skew") }
        guard !tok.certificates.isEmpty else { throw DERError("TSA token without certificates") }
        return tok
    }

    // MARK: - Parsing

    struct Parsed {
        let token: Token
        let eContent: [UInt8]
        let signerInfo: DER
    }

    static func parse(_ der: [UInt8], expectedHash: [UInt8], nonce: [UInt8]) throws -> Parsed {
        let resp = try DER.parse(der).expect(0x30)
        let r = try resp.children()
        guard r.count >= 2 else { throw DERError("TimeStampResp without token") }
        let status = try r[0].child(0).expect(0x02).unsignedInteger
        guard status == [0] || status == [1] else { throw DERError("TSA status \(status)") }
        let tokenE = try r[1].expect(0x30)
        let ci = try tokenE.children()
        guard ci.count == 2, ci[0].oid == OID.signedData else { throw DERError("token is not SignedData") }
        let sd = try ci[1].expect(0xA0).child(0).children()
        guard sd.count >= 4 else { throw DERError("SignedData shape") }
        let encap = try sd[2].children()
        guard encap.count == 2, encap[0].oid == OID.tstInfo else { throw DERError("eContentType is not TSTInfo") }
        let eContent = try encap[1].expect(0xA0).child(0).expect(0x04).contents
        var certs: [X509Cert] = []
        var idx = 3
        if sd[idx].tag == 0xA0 {
            certs = try sd[idx].children().filter { $0.tag == 0x30 }.map { try X509Cert(der: $0.bytes) }
            idx += 1
        }
        if idx < sd.count, sd[idx].tag == 0xA1 { idx += 1 }
        guard idx < sd.count, let si = try sd[idx].expect(0x31).children().first else { throw DERError("no SignerInfo") }

        let tst = try DER.parse(eContent).children()
        guard tst.count >= 5 else { throw DERError("TSTInfo shape") }
        let imprint = try tst[2].children()
        guard try imprint[0].child(0).oid == OID.sha256, try imprint[1].expect(0x04).contents == expectedHash else {
            throw DERError("timestamp hash does not match")
        }
        guard let gen = tst[4].time else { throw DERError("genTime") }
        var gotNonce: [UInt8]?
        for e in tst.dropFirst(5) where e.tag == 0x02 { gotNonce = e.unsignedInteger }
        guard let gotNonce, gotNonce == DER.minimal(nonce) else { throw DERError("nonce mismatch") }
        return Parsed(token: Token(raw: tokenE.bytes, genTime: gen, certificates: certs), eContent: eContent, signerInfo: si)
    }

    /// Token signature (digitorus `ParseResponse` → pkcs7 Verify): signer by issuerAndSerial,
    /// messageDigest == H(eContent), signature over the DER SET of signedAttrs. Returns the signer certificate.
    static func verifySignature(_ p: Parsed) throws -> X509Cert {
        let t = p.token
        let si = try p.signerInfo.children()
        guard si.count >= 5 else { throw DERError("SignerInfo shape") }
        let sid = si[1]
        var signer: X509Cert?
        if sid.tag == 0x30 {
            let ias = try sid.children()
            let serial = DER.minimal(try ias[1].expect(0x02).contents)
            signer = t.certificates.first { $0.rawIssuer == ias[0].bytes && DER.minimal($0.serial) == serial }
        }
        guard let signer else { throw DERError("TSA signer certificate not found") }
        let digestAlg = try si[2].child(0).oid ?? ""
        guard si[3].tag == 0xA0 else { throw DERError("token without signedAttrs") }
        var md: [UInt8]?
        for a in try si[3].children() {
            let q = try a.children()
            if q.count == 2, q[0].oid == OID.messageDigest { md = try q[1].child(0).expect(0x04).contents }
        }
        let content: [UInt8]
        switch digestAlg {
        case OID.sha256: content = Crypto.sha256(p.eContent)
        case OID.sha384: content = Array(SHA384Digest(p.eContent))
        case OID.sha512: content = Array(SHA512Digest(p.eContent))
        default: throw DERError("TSA digest algorithm \(digestAlg)")
        }
        guard md == content else { throw DERError("TSA messageDigest") }
        var setAttrs = si[3].bytes
        setAttrs[0] = 0x31
        let sigAlgOID = try si[4].child(0).oid ?? ""
        let sig = try si[5].expect(0x04).contents
        guard Crypto.verify(alg: signatureAlgorithm(sigAlgOID, digest: digestAlg), key: signer, data: setAttrs, signature: sig) else {
            throw DERError("TSA token signature")
        }
        return signer
    }

    /// rsaEncryption in SignerInfo means "RSA PKCS#1 v1.5 with the digest algorithm".
    static func signatureAlgorithm(_ oid: String, digest: String) -> String {
        guard oid == OID.rsaEncryption else { return oid }
        switch digest {
        case OID.sha384: return OID.sha384WithRSA
        case OID.sha512: return OID.sha512WithRSA
        default: return OID.sha256WithRSA
        }
    }

    /// Exactly one EKU extension, critical, = {timeStamping} (Go `eidcrypto.IsTSASigningCert`).
    static func isTSASigningCert(_ c: X509Cert) -> Bool {
        c.extKeyUsageCritical && c.extKeyUsage == [OID.kpTimeStamping]
    }

    /// `leaf` chains to one of `roots` through `pool` — Go `x509.Verify` (verifyTSAChain, KeyUsages timeStamping):
    /// subject/issuer + signature, every certificate valid at `at`, each issuer a CA allowed to sign certificates
    /// (cA + keyCertSign; intermediates must carry basicConstraints), pathLenConstraint and the EKU of every issuer
    /// (empty, anyExtendedKeyUsage or timeStamping).
    static func chainsToRoot(_ leaf: X509Cert, pool: [X509Cert], roots: [X509Cert], at: Date) -> Bool {
        func ekuOK(_ c: X509Cert) -> Bool {
            c.extKeyUsage.isEmpty || c.extKeyUsage.contains(OID.anyExtendedKeyUsage) || c.extKeyUsage.contains(OID.kpTimeStamping)
        }
        var cur = leaf
        var below = 0  // CA certificates between the leaf and the next issuer (Go numIntermediates)
        for _ in 0..<8 {
            guard cur.validAt(at) else { return false }
            if roots.contains(where: { cur.isSigned(by: $0) && $0.validAt(at) && $0.allowsPath(below: below) && ekuOK($0) }) {
                return true
            }
            guard let next = pool.first(where: {
                $0 != cur && cur.isSigned(by: $0) && $0.basicConstraintsValid && $0.isCA && $0.allowsPath(below: below) && ekuOK($0)
            }) else { return false }
            cur = next
            below += 1
        }
        return false
    }
}

import CryptoKit

private func SHA384Digest(_ b: [UInt8]) -> [UInt8] { Array(SHA384.hash(data: b)) }
private func SHA512Digest(_ b: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: b)) }
