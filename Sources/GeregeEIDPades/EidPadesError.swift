import Foundation

/// Stable error codes shared by every eID PAdES SDK (Go reference `pades/errors.go`; Android
/// `EidPadesException.code` carries the same strings).
public struct EidPadesError: Error, Equatable, Sendable, CustomStringConvertible {
    public enum Code: String, Sendable, CaseIterable {
        case pdfInvalid = "PDF_INVALID"
        case pdfEncrypted = "PDF_ENCRYPTED"
        /// DocMDP P=1 — further signing forbidden.
        case pdfLocked = "PDF_LOCKED"
        case pdfTooLarge = "PDF_TOO_LARGE"
        case pdfTooManySignatures = "PDF_TOO_MANY_SIGNATURES"
        case pdfPriorSignatureInvalid = "PDF_PRIOR_SIGNATURE_INVALID"
        /// A prior signature is not an eID PAdES-BASELINE-LT signature.
        case pdfForeignSignature = "PDF_FOREIGN_SIGNATURE"
        case signerInvalid = "SIGNER_INVALID"
        case requestInvalid = "REQUEST_INVALID"
        case signatureInvalid = "SIGNATURE_INVALID"
        case tsaUnavailable = "TSA_UNAVAILABLE"
        case ltvUnavailable = "LTV_UNAVAILABLE"
        case selfValidationFailed = "SELF_VALIDATION_FAILED"
        case placeholderOverflow = "PLACEHOLDER_OVERFLOW"
        case stateInvalid = "STATE_INVALID"
        case `internal` = "INTERNAL"
    }

    public let code: Code
    /// Developer-facing detail (not for end users).
    public let message: String
    /// `complete`: a chain certificate (citizen, issuer or TSA) is revoked by its issuer-signed OCSP response or CRL
    /// (code `LTV_UNAVAILABLE`, Go `pades.ErrCertificateRevoked`). Final — retrying with the same state does not help.
    public let certificateRevoked: Bool

    public init(code: Code, message: String, certificateRevoked: Bool = false) {
        self.code = code
        self.message = message
        self.certificateRevoked = certificateRevoked
    }

    /// TSA_UNAVAILABLE / LTV_UNAVAILABLE (temporary — call `complete` again with the same state and signature), except a
    /// revoked certificate.
    public var retryable: Bool { !certificateRevoked && (code == .tsaUnavailable || code == .ltvUnavailable) }

    public var description: String { "\(code.rawValue): \(message)" }
}
