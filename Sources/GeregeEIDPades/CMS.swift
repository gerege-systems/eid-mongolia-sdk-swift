import Foundation

/// CMS SignedData (CAdES baseline, detached) — 1:1 port of the Go reference `pades/internal/core/cms.go`.
enum CMS {
    /// claimedRole limit in characters (Go `ClaimedRoleMaxRunes`).
    static let claimedRoleMaxRunes = 900

    /// DER SET OF Attribute (tag 0x31): contentType = id-data, messageDigest, signingCertificateV2 (ESSCertIDv2:
    /// certHash = SHA-256(cert), issuerSerial), + signer-attributes-v2 claimedAttributes{id-at-role UTF8String}
    /// when `claimedRole` is non-empty. No signingTime (PAdES baseline).
    static func signedAttributes(messageDigest: [UInt8], signer: X509Cert, claimedRole: String) throws -> [UInt8] {
        guard messageDigest.count == 32 else { throw DERError("messageDigest is not SHA-256") }
        guard claimedRole.unicodeScalars.count <= claimedRoleMaxRunes else { throw DERError("claimed role too long") }
        func attr(_ oid: String, _ value: [UInt8]) -> [UInt8] { DERW.seq(DERW.oid(oid), DERW.set([value])) }
        let issuerSerial = DERW.seq(
            DERW.seq(DERW.tlv(0xA4, signer.rawIssuer)),   // GeneralNames { directoryName [4] EXPLICIT Name }
            DERW.tlv(0x02, signer.serial))
        var attrs = [
            attr(OID.contentType, DERW.oid(OID.data)),
            attr(OID.messageDigest, DERW.octet(messageDigest)),
            attr(OID.signingCertV2, DERW.seq(DERW.seq(DERW.seq(DERW.octet(Crypto.sha256(signer.raw)), issuerSerial)))),
        ]
        if !claimedRole.isEmpty {
            let role = DERW.seq(DERW.oid(OID.role), DERW.set([DERW.utf8(claimedRole)]))
            attrs.append(attr(OID.signerAttrV2, DERW.seq(DERW.tlv(0xA0, DERW.seq(role)))))
        }
        return DERW.sortedSet(attrs)
    }

    /// SHA-256(DER(signedAttrs)) — what the phone/token signs.
    static func dtbs(_ signedAttrs: [UInt8]) -> [UInt8] { Crypto.sha256(signedAttrs) }

    /// ContentInfo{SignedData}: certificates = signer + chain (sorted DER SET), one SignerInfo with
    /// [0] IMPLICIT signedAttrs and [1] unsignedAttrs = signatureTimeStampToken.
    static func assemble(signedAttrs: [UInt8], signer: X509Cert, chain: [X509Cert], signature: [UInt8],
                         timestampToken tst: [UInt8]) throws -> [UInt8] {
        guard signedAttrs.count >= 2, signedAttrs[0] == 0x31 else { throw DERError("signedAttrs is not a DER SET") }
        let sigAlg: [UInt8]
        if signer.isRSA {
            sigAlg = DERW.algID(OID.sha256WithRSA, nullParams: true)
        } else if signer.isEC {
            sigAlg = DERW.algID(OID.ecdsaWithSHA256, nullParams: false)
        } else {
            throw DERError("unsupported signer key")
        }
        var implicitAttrs = signedAttrs
        implicitAttrs[0] = 0xA0
        var certs = [signer.raw]
        for c in chain where c != signer { certs.append(c.raw) }
        certs.sort { $0.lexicographicallyPrecedes($1) }
        var signerInfo: [[UInt8]] = [
            DERW.int(1),
            DERW.seq(signer.rawIssuer, DERW.tlv(0x02, signer.serial)),
            DERW.algID(OID.sha256, nullParams: false),
            implicitAttrs,
            sigAlg,
            DERW.octet(signature),
        ]
        if !tst.isEmpty {
            signerInfo.append(DERW.tlv(0xA1, DERW.seq(DERW.oid(OID.timeStampToken), DERW.set([tst]))))
        }
        let signedData = DERW.seq(
            DERW.int(1),
            DERW.set([DERW.algID(OID.sha256, nullParams: false)]),
            DERW.seq(DERW.oid(OID.data)),
            DERW.tlv(0xA0, certs.flatMap { $0 }),
            DERW.set([DERW.seq(signerInfo)]))
        return DERW.seq(DERW.oid(OID.signedData), DERW.tlv(0xA0, signedData))
    }

    /// GIVENNAME SURNAME from the certificate (as written, Latin); else CN (Go `SignerDisplayName`).
    static func signerDisplayName(_ c: X509Cert) -> String {
        let given = c.subject(OID.givenName) ?? "", sur = c.subject(OID.surname) ?? ""
        let name = (given + " " + sur).trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? c.commonName : name
    }
}
