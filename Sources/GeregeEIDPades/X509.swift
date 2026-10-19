import CryptoKit
import Foundation
import Security

/// The parts of an X.509 certificate the signing path uses (RFC 5280). Parsing is structural; signature checks go
/// through Security.framework.
struct X509Cert: Equatable {
    let raw: [UInt8]
    let tbs: [UInt8]
    /// DER of the issuer / subject Name (Go `RawIssuer` / `RawSubject`).
    let rawIssuer: [UInt8]
    let rawSubject: [UInt8]
    /// Serial number INTEGER contents (two's complement, as encoded).
    let serial: [UInt8]
    let notBefore: Date
    let notAfter: Date
    /// SubjectPublicKeyInfo DER and the BIT STRING key bytes (without the unused-bits octet).
    let spki: [UInt8]
    let publicKeyBits: [UInt8]
    let keyAlgorithm: String
    let sigAlgorithm: String
    let signature: [UInt8]
    let ocspServers: [String]
    let crlDistributionPoints: [String]
    let extKeyUsage: [String]
    let extKeyUsageCritical: Bool
    let subjectAttrs: [(oid: String, value: String)]
    /// Go `Version` (1…3), `BasicConstraintsValid`, `IsCA`, `MaxPathLen` (nil = no limit), `KeyUsage` (bit i = 1 << i),
    /// `SubjectKeyId`.
    let version: Int
    let basicConstraintsValid: Bool
    let isCA: Bool
    let maxPathLen: Int?
    let keyUsage: Int
    let subjectKeyId: [UInt8]

    static let keyUsageCertSign = 1 << 5
    static let keyUsageCRLSign = 1 << 6

    static func == (a: X509Cert, b: X509Cert) -> Bool { a.raw == b.raw }

    var isRSA: Bool { keyAlgorithm == OID.rsaEncryption }
    var isEC: Bool { keyAlgorithm == OID.ecPublicKey }

    func subject(_ oid: String) -> String? { subjectAttrs.first { $0.oid == oid }?.value }
    var commonName: String { subject(OID.commonName) ?? "" }

    /// Issuer CN (Go `cert.Issuer.CommonName`).
    var issuerCommonName: String {
        guard let name = try? DER.parse(rawIssuer) else { return "" }
        var cn = ""
        for rdn in (try? name.children()) ?? [] {
            for atv in (try? rdn.children()) ?? [] {
                if let p = try? atv.children(), p.count == 2, p[0].oid == OID.commonName, let v = p[1].string { cn = v }
            }
        }
        return cn
    }

    init(der: [UInt8]) throws {
        let cert = try DER.parse(der).expect(0x30)
        guard cert.raw.count == der.count else { throw DERError("trailing data after certificate") }
        let top = try cert.children()
        guard top.count == 3 else { throw DERError("certificate shape") }
        let tbsE = try top[0].expect(0x30)
        raw = der
        tbs = tbsE.bytes
        sigAlgorithm = try top[1].child(0).oid ?? ""
        let sigBits = try top[2].expect(0x03).contents
        guard let first = sigBits.first, first == 0 else { throw DERError("signature bit string") }
        signature = Array(sigBits.dropFirst())

        var f = try tbsE.children()
        var v = 1
        if f.first?.tag == 0xA0 {                     // version
            let n = try f[0].child(0).expect(0x02).unsignedInteger
            guard n.count == 1, n[0] <= 2 else { throw DERError("certificate version") }
            v = Int(n[0]) + 1
            f.removeFirst()
        }
        version = v
        guard f.count >= 6 else { throw DERError("tbsCertificate shape") }
        serial = try f[0].expect(0x02).contents
        rawIssuer = try f[2].expect(0x30).bytes
        let validity = try f[3].children()
        guard validity.count == 2, let nb = validity[0].time, let na = validity[1].time else { throw DERError("validity") }
        notBefore = nb
        notAfter = na
        rawSubject = try f[4].expect(0x30).bytes
        let spkiE = try f[5].expect(0x30)
        spki = spkiE.bytes
        keyAlgorithm = try spkiE.child(0).child(0).oid ?? ""
        let keyBits = try spkiE.child(1).expect(0x03).contents
        guard keyBits.first == 0 else { throw DERError("public key bit string") }
        publicKeyBits = Array(keyBits.dropFirst())

        var attrs: [(String, String)] = []
        for rdn in try f[4].children() {
            for atv in try rdn.children() {
                let p = try atv.children()
                if p.count == 2, let o = p[0].oid, let v = p[1].string { attrs.append((o, v)) }
            }
        }
        subjectAttrs = attrs

        var ocsp: [String] = [], crl: [String] = [], eku: [String] = []
        var ekuCritical = false
        var bcValid = false, ca = false, pathLen: Int?, ku = 0, ski: [UInt8] = []
        if let extWrap = f.first(where: { $0.tag == 0xA3 }) {
            for ext in try extWrap.child(0).children() {
                let p = try ext.children()
                guard let o = p.first?.oid else { continue }
                let critical = p.count == 3 && p[1].tag == 0x01 && p[1].value.first == 0xFF
                guard let valueE = p.last, valueE.tag == 0x04 else { continue }
                let inner = try DER.parse(valueE.value)
                switch o {
                case OID.authorityInfoAccess:
                    for ad in try inner.children() {
                        let q = try ad.children()
                        if q.count == 2, q[0].oid == OID.ocspAccess, q[1].tag == 0x86 {
                            ocsp.append(String(decoding: q[1].value, as: UTF8.self))
                        }
                    }
                case OID.crlDistributionPoints:
                    for dp in try inner.children() {
                        // DistributionPoint { distributionPoint [0] { fullName [0] GeneralNames } }
                        guard let dpn = try dp.children().first(where: { $0.tag == 0xA0 }),
                              let full = try dpn.children().first(where: { $0.tag == 0xA0 }) else { continue }
                        for gn in try full.children() where gn.tag == 0x86 {
                            crl.append(String(decoding: gn.value, as: UTF8.self))
                        }
                    }
                case OID.extKeyUsage:
                    eku = try inner.children().compactMap(\.oid)
                    ekuCritical = critical
                case OID.basicConstraints:
                    // BasicConstraints { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
                    bcValid = true
                    for e in try inner.expect(0x30).children() {
                        if e.tag == 0x01 { ca = e.value.first.map { $0 != 0 } ?? false }
                        if e.tag == 0x02 {
                            let n = e.unsignedInteger
                            guard e.value.first.map({ $0 & 0x80 == 0 }) ?? false, n.count <= 4 else {
                                throw DERError("basicConstraints pathLen")
                            }
                            pathLen = n.reduce(0) { $0 << 8 | Int($1) }
                        }
                    }
                case OID.keyUsage:
                    // Go: bit i of the BIT STRING (MSB first) → KeyUsage 1 << i, i < 9.
                    let bits = Array(try inner.expect(0x03).value.dropFirst())
                    for i in 0..<9 where i / 8 < bits.count && bits[i / 8] & (0x80 >> UInt8(i % 8)) != 0 { ku |= 1 << i }
                case OID.subjectKeyId:
                    ski = try inner.expect(0x04).contents
                default:
                    break
                }
            }
        }
        ocspServers = ocsp
        crlDistributionPoints = crl
        extKeyUsage = eku
        extKeyUsageCritical = ekuCritical
        basicConstraintsValid = bcValid
        isCA = ca
        maxPathLen = ca ? pathLen : nil
        keyUsage = ku
        subjectKeyId = ski
    }

    /// Security.framework public key.
    func secKey() throws -> SecKey {
        guard let c = SecCertificateCreateWithData(nil, Data(raw) as CFData), let k = SecCertificateCopyKey(c) else {
            throw DERError("public key not usable")
        }
        return k
    }

    /// EC key size in bytes (P-256 → 32), from the uncompressed point length.
    var ecFieldBytes: Int { (publicKeyBits.count - 1) / 2 }

    /// `self` was signed by `issuer` (Go `bytes.Equal(RawIssuer, issuer.RawSubject) && CheckSignatureFrom(issuer)`):
    /// the issuer must be a CA allowed to sign certificates (basicConstraints cA, keyUsage keyCertSign when present).
    func isSigned(by issuer: X509Cert) -> Bool {
        rawIssuer == issuer.rawSubject && issuer.mayIssue(Self.keyUsageCertSign)
            && Crypto.verify(alg: sigAlgorithm, key: issuer, data: tbs, signature: signature)
    }

    /// Go `CheckSignatureFrom` / `RevocationList.CheckSignatureFrom` parent checks: a v3 certificate needs
    /// basicConstraints with cA = true (v1/v2 without the extension are accepted, like Go); a keyUsage extension, when
    /// present and non-empty, must include `usage` (keyCertSign for certificates, cRLSign for CRLs).
    func mayIssue(_ usage: Int) -> Bool {
        if version == 3 && !basicConstraintsValid || basicConstraintsValid && !isCA { return false }
        return keyUsage == 0 || keyUsage & usage != 0
    }

    /// Go `Verify` path-length rule: `intermediates` CA certificates below this one in the chain.
    func allowsPath(below intermediates: Int) -> Bool {
        guard basicConstraintsValid, let max = maxPathLen else { return true }
        return intermediates <= max
    }

    func validAt(_ t: Date) -> Bool { notBefore <= t && t <= notAfter }

    /// Serial in lower-case hex without leading zeros (Go `SerialNumber.Text(16)`) — errors name certificates by
    /// serial, never by CN (the citizen's name is PII).
    var serialRef: String {
        let h = Crypto.hex(DER.minimal(serial)).drop { $0 == "0" }
        return "serial " + (h.isEmpty ? "0" : String(h))
    }
}

enum Crypto {
    /// Verifies `signature` over `data` with an X.509 signature algorithm OID.
    static func verify(alg: String, key cert: X509Cert, data: [UInt8], signature: [UInt8]) -> Bool {
        let a: SecKeyAlgorithm
        switch alg {
        case OID.sha256WithRSA: a = .rsaSignatureMessagePKCS1v15SHA256
        case OID.sha384WithRSA: a = .rsaSignatureMessagePKCS1v15SHA384
        case OID.sha512WithRSA: a = .rsaSignatureMessagePKCS1v15SHA512
        case OID.ecdsaWithSHA256: a = .ecdsaSignatureMessageX962SHA256
        case OID.ecdsaWithSHA384: a = .ecdsaSignatureMessageX962SHA384
        case OID.ecdsaWithSHA512: a = .ecdsaSignatureMessageX962SHA512
        default: return false
        }
        guard let k = try? cert.secKey() else { return false }
        return SecKeyVerifySignature(k, a, Data(data) as CFData, Data(signature) as CFData, nil)
    }

    /// Verifies a signature over an already computed SHA-256 digest (the citizen's DTBS).
    static func verifyDigest(key cert: X509Cert, digest: [UInt8], signature: [UInt8]) -> Bool {
        guard let k = try? cert.secKey() else { return false }
        let a: SecKeyAlgorithm = cert.isRSA ? .rsaSignatureDigestPKCS1v15SHA256 : .ecdsaSignatureDigestX962SHA256
        return SecKeyVerifySignature(k, a, Data(digest) as CFData, Data(signature) as CFData, nil)
    }

    static func sha256(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: b)) }

    static func digest(_ alg: String, _ b: [UInt8]) -> [UInt8]? {
        switch alg {
        case OID.sha1: return sha1(b)
        case OID.sha256: return sha256(b)
        case OID.sha384: return Array(SHA384.hash(data: b))
        case OID.sha512: return Array(SHA512.hash(data: b))
        default: return nil
        }
    }

    static func ecdsaAlgorithm(digest: String) -> String {
        switch digest {
        case OID.sha384: return OID.ecdsaWithSHA384
        case OID.sha512: return OID.ecdsaWithSHA512
        default: return OID.ecdsaWithSHA256
        }
    }
    static func sha1(_ b: [UInt8]) -> [UInt8] { Array(Insecure.SHA1.hash(data: b)) }
    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
