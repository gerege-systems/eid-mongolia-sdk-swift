import Foundation

/// Opaque prepare → complete state. Same layout as the Go reference (`pades/state.go`):
/// "EIDPADES1" ‖ uint32 BE header length ‖ JSON header ‖ prepared PDF (the PDF is not base64-encoded).
struct State: Codable {
    static let magic = Array("EIDPADES1".utf8)

    var docId: String
    var signerCert: [UInt8]
    var chain: [[UInt8]]
    var signedAttrs: [UInt8]
    var byteRange: [Int]
    var revIndex: Int
    var inSha256: String
    var hasPage: Bool
    var pageSha256: String?
    var claimedRole: String?
    /// Cleaned document name for the CA registration (Go `prepState.FileName`).
    var fileName: String?
    var preparedSha256: String
    var pdf: [UInt8] = []

    enum CodingKeys: String, CodingKey {
        case docId, signerCert, chain, signedAttrs, byteRange, revIndex, inSha256, hasPage, pageSha256, claimedRole,
             fileName, preparedSha256
    }

    init(docId: String, signerCert: [UInt8], chain: [[UInt8]], signedAttrs: [UInt8], byteRange: [Int], revIndex: Int,
         inSha256: String, hasPage: Bool, pageSha256: String?, claimedRole: String?, fileName: String? = nil,
         preparedSha256: String, pdf: [UInt8]) {
        self.docId = docId
        self.signerCert = signerCert
        self.chain = chain
        self.signedAttrs = signedAttrs
        self.byteRange = byteRange
        self.revIndex = revIndex
        self.inSha256 = inSha256
        self.hasPage = hasPage
        self.pageSha256 = pageSha256
        self.claimedRole = claimedRole
        self.fileName = fileName
        self.preparedSha256 = preparedSha256
        self.pdf = pdf
    }

    // []byte as base64 strings (Go encoding/json).
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func b64(_ s: String) throws -> [UInt8] {
            guard let d = Data(base64Encoded: s) else { throw DERError("base64") }
            return [UInt8](d)
        }
        docId = try c.decode(String.self, forKey: .docId)
        signerCert = try b64(c.decode(String.self, forKey: .signerCert))
        chain = try (c.decodeIfPresent([String].self, forKey: .chain) ?? []).map(b64)
        signedAttrs = try b64(c.decode(String.self, forKey: .signedAttrs))
        byteRange = try c.decode([Int].self, forKey: .byteRange)
        revIndex = try c.decode(Int.self, forKey: .revIndex)
        inSha256 = try c.decode(String.self, forKey: .inSha256)
        hasPage = try c.decode(Bool.self, forKey: .hasPage)
        pageSha256 = try c.decodeIfPresent(String.self, forKey: .pageSha256)
        claimedRole = try c.decodeIfPresent(String.self, forKey: .claimedRole)
        fileName = try c.decodeIfPresent(String.self, forKey: .fileName)
        preparedSha256 = try c.decode(String.self, forKey: .preparedSha256)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(docId, forKey: .docId)
        try c.encode(Data(signerCert).base64EncodedString(), forKey: .signerCert)
        try c.encode(chain.map { Data($0).base64EncodedString() }, forKey: .chain)
        try c.encode(Data(signedAttrs).base64EncodedString(), forKey: .signedAttrs)
        try c.encode(byteRange, forKey: .byteRange)
        try c.encode(revIndex, forKey: .revIndex)
        try c.encode(inSha256, forKey: .inSha256)
        try c.encode(hasPage, forKey: .hasPage)
        try c.encodeIfPresent(pageSha256, forKey: .pageSha256)
        try c.encodeIfPresent(claimedRole, forKey: .claimedRole)
        try c.encodeIfPresent(fileName, forKey: .fileName)
        try c.encode(preparedSha256, forKey: .preparedSha256)
    }

    func encode() throws -> [UInt8] {
        let head = [UInt8](try JSONEncoder().encode(self))
        let n = UInt32(head.count)
        return Self.magic + [UInt8(n >> 24 & 0xFF), UInt8(n >> 16 & 0xFF), UInt8(n >> 8 & 0xFF), UInt8(n & 0xFF)] + head + pdf
    }

    static func decode(_ b: [UInt8]) throws -> State {
        guard b.starts(with: magic), b.count >= magic.count + 4 else { throw DERError("unknown state header") }
        let p = magic.count
        let n = Int(b[p]) << 24 | Int(b[p + 1]) << 16 | Int(b[p + 2]) << 8 | Int(b[p + 3])
        guard n <= b.count - p - 4 else { throw DERError("state truncated") }
        var s = try JSONDecoder().decode(State.self, from: Data(b[(p + 4)..<(p + 4 + n)]))
        s.pdf = Array(b[(p + 4 + n)...])
        guard Crypto.hex(Crypto.sha256(s.pdf)) == s.preparedSha256 else { throw DERError("prepared PDF hash mismatch") }
        guard !s.signedAttrs.isEmpty, !s.signerCert.isEmpty, !s.pdf.isEmpty, s.revIndex >= 1, s.byteRange.count == 4 else {
            throw DERError("state incomplete")
        }
        return s
    }
}
