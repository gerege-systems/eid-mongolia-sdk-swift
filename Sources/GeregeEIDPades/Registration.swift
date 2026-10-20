import Foundation

extension EidPades {
    /// `phone` (RP-API RAW_DIGEST_SIGNATURE session, `sessionId` required) | `token` (USB token).
    public enum Medium: String, Sendable, Encodable {
        case phone, token
    }

    /// One prior signature's two keys (Go `eid.PDFPriorSignature`): the CA knows a client-side row by its CMS hash and a
    /// CA-assembled (mode A) row by its revision hash — which one a prior signature is cannot be told from the file.
    public struct PriorSignature: Sendable, Equatable {
        public let cmsSha256: String
        public let revisionSha256: String
    }

    /// Body of CA `POST /pdf/signatures` (CA `dto.PDFSignatureRegisterRequest`, Go `eid.PDFSignatureRegistration`,
    /// TS `RegisterSignatureInput`) — encode with `JSONEncoder` and post it from the RP backend as is. Field names
    /// are exact (the CA rejects unknown fields). Built by `Completed.registration(medium:sessionId:onBehalfOf:)`.
    public struct Registration: Encodable, Sendable, Equatable {
        public var docID: String
        public var revIndex: Int
        public var medium: Medium
        public var sessionID: String?
        /// CMS DER, standard base64.
        public var cms: String
        public var fileName: String
        public var inSha256: String
        /// Only for revIndex 1 (the document with the verification page).
        public var pageSha256: String?
        public var sigRevSha256: String
        public var outSha256: String
        /// Prior signatures identified by CMS hash (client-side rows) — the default.
        public var priorCmsSha256: [String]?
        /// Prior CA-assembled (mode A) signatures by revision hash. nil by default; on 409 `PRIOR_MISMATCH` move the
        /// matching entries of `priorSignatures` from `priorCmsSha256` to here (Go `RegisterSignature` does it itself).
        public var priorRevisionSha256: [String]?
        public var onBehalfOf: String?
        /// Signer certificate SERIALNUMBER (PNOMN-…); the CA checks it against the CMS signer.
        public var signerEtsi: String?
        /// SDK-only (never encoded): every prior signature's CMS and revision hash, document order.
        public var priorSignatures: [PriorSignature] = []

        enum CodingKeys: String, CodingKey {
            case docID, revIndex, medium, sessionID, cms, fileName, inSha256, pageSha256, sigRevSha256, outSha256,
                 priorCmsSha256, priorRevisionSha256, onBehalfOf, signerEtsi
        }
    }
}

extension EidPades.Completed {
    /// The CA registration body for this signature (Go `pades.Registration`). Prior signatures go as `priorCmsSha256`
    /// only — sending the same signatures in `priorRevisionSha256` too is rejected by the CA (400).
    ///
    /// `medium` nil = inferred the way the CA pairs them: `sessionId` given → `.phone`, else `.token`.
    /// - Throws: `REQUEST_INVALID` when revIndex is 1 without a verification page, prepare had no valid `fileName`,
    ///   `.phone` has no `sessionId`, `.token` has a `sessionId`, or `claimedRole` was prepared without `onBehalfOf`.
    public func registration(medium: EidPades.Medium? = nil, sessionId: String? = nil,
                             onBehalfOf: String? = nil) throws -> EidPades.Registration {
        if revIndex == 1 && !hasPage {
            throw EidPadesError(code: .requestInvalid,
                                message: "the CA registers a first signature only with the verification page (PrepareOptions.verifyPage)")
        }
        guard let fileName, !fileName.isEmpty else {
            throw EidPadesError(code: .requestInvalid, message: "fileName empty (PrepareOptions.fileName)")
        }
        let session = sessionId?.nilIfEmpty
        let medium = medium ?? (session != nil ? .phone : .token)
        switch (medium, session) {
        case (.phone, nil):
            throw EidPadesError(code: .requestInvalid, message: "medium phone requires sessionId (the RAW_DIGEST_SIGNATURE session)")
        case (.token, .some):
            throw EidPadesError(code: .requestInvalid, message: "medium token takes no sessionId")
        default: break
        }
        if claimedRole?.nilIfEmpty != nil, onBehalfOf?.nilIfEmpty == nil {
            throw EidPadesError(code: .requestInvalid, message: "claimedRole was prepared: onBehalfOf (NTRMN-…) is required")
        }
        var r = EidPades.Registration(
            docID: docId, revIndex: revIndex, medium: medium, sessionID: session, cms: cms.base64EncodedString(),
            fileName: fileName, inSha256: inSha256, pageSha256: revIndex == 1 ? pageSha256 : nil,
            sigRevSha256: sigRevSha256, outSha256: outSha256, onBehalfOf: onBehalfOf?.nilIfEmpty)
        if !priorCmsSha256.isEmpty {
            r.priorCmsSha256 = priorCmsSha256
            if priorRevisionSha256.count == priorCmsSha256.count {
                r.priorSignatures = zip(priorCmsSha256, priorRevisionSha256).map {
                    EidPades.PriorSignature(cmsSha256: $0, revisionSha256: $1)
                }
            }
        }
        if let cert = try? X509Cert(der: [UInt8](signerCert)) {
            r.signerEtsi = cert.subjectAttrs.last { $0.oid == OID.serialNumber }?.value
        }
        return r
    }
}
