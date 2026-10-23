// GeregeEIDPades — client-side PAdES (PAdES-BASELINE-LT) for iOS + macOS, native Swift.
//
// The PDF never leaves the device (Smart-ID model): `prepare` writes the signature revision locally and returns the
// 32-byte DTBS the phone (ACSP_V2 / RAW_DIGEST_SIGNATURE) or a USB token signs; `complete` checks that signature,
// fetches an RFC 3161 timestamp, assembles the CMS, embeds it and appends the DSS (OCSP/CRL) revision.
//
// Reference implementation = gerege-systems/eid-mongolia-sdk-go `pades` (Go). This port must reproduce the Go
// golden vectors byte for byte (Tests/GeregeEIDPadesTests/golden, scripts/sync-pades-golden.sh). No full
// validator here (that stays in the Go backend SDK). API names 1:1 with Android `mn.eidmongolia.eid.pades.EidPades`.
import Foundation

public enum EidPades {
    /// PDF/CMS profile version (Go `pades.ProfileVersion`).
    public static let version = "pades-client/1"

    /// Prepare input limit (10 MiB − 256 KiB) and output limit (10 MiB) — Go `MaxInputBytes` / `MaxOutputBytes`.
    static let maxInputBytes = (10 << 20) - (256 << 10)
    static let maxOutputBytes = 10 << 20
    static let maxSignatures = 16
    static let maxFileName = 120

    /// /M and the verify page are written in Ulaanbaatar time (+08:00), like the CA and the Go reference.
    static let signingTimeZone = TimeZone(identifier: "Asia/Ulaanbaatar") ?? TimeZone(secondsFromGMT: 8 * 3600)!

    // MARK: - Types

    public struct PrepareOptions: Sendable {
        /// Citizen SIGN certificate (DER) — signingCertificateV2.
        public var signerCert: Data
        /// Issuer chain DER (04, 03, 02). nil → built from the embedded eID chain.
        public var chain: [Data]?
        /// PDF /Name. nil → certificate GIVENNAME SURNAME (else CN).
        public var signerName: String?
        /// PDF /Reason (≤ 127 UTF-16 units, else omitted).
        public var reason: String?
        /// CA-confirmed representation (`claimedRole` from the CA representation response) → signer-attributes-v2.
        public var claimedRole: String?
        /// /M. nil → now.
        public var signingTime: Date?
        /// Document UUID (verify page/QR). nil → generated for the first eID signature, read from the page otherwise.
        public var docId: String?
        /// Append the verification (QR) page — only for an unsigned document (first eID signature).
        public var verifyPage: Bool
        /// Where the verification page goes when it is added (verifyPage on an unsigned document): "last" (default; also
        /// nil/empty) or "first" (it becomes page 1). `appearance.page`, `suggestPlacement` and `placement.page` always
        /// count the pages of the input PDF as given — never the added page (PAGE_SPEC §8a, PLACEMENT_SPEC §1b). Other
        /// values → REQUEST_INVALID.
        public var verifyPagePosition: String?
        /// Document name shown on the page (required with verifyPage; ≤ 120 characters).
        public var fileName: String?
        /// Verification page language "mn" (default) | "en".
        public var lang: String?
        /// Visible signature (APPEARANCE_SPEC.md); nil → invisible (default, byte-identical to before).
        public var appearance: SignatureAppearance?

        public init(signerCert: Data, chain: [Data]? = nil, signerName: String? = nil, reason: String? = nil,
                    claimedRole: String? = nil, signingTime: Date? = nil, docId: String? = nil,
                    verifyPage: Bool = false, fileName: String? = nil, lang: String? = nil,
                    appearance: SignatureAppearance? = nil, verifyPagePosition: String? = nil) {
            self.signerCert = signerCert
            self.chain = chain
            self.signerName = signerName
            self.reason = reason
            self.claimedRole = claimedRole
            self.signingTime = signingTime
            self.docId = docId
            self.verifyPage = verifyPage
            self.fileName = fileName
            self.lang = lang
            self.appearance = appearance
            self.verifyPagePosition = verifyPagePosition
        }
    }

    /// Visible signature placement (Go `pades.Appearance`, APPEARANCE_SPEC.md §1). Points, from the bottom-left corner
    /// of the page's CropBox (else MediaBox) as DISPLAYED (after /Rotate); x to the right, y up; rounded to 0.01 pt.
    /// Height ≥ 45 pt (QR), else REQUEST_INVALID. width = height = 0 → the default size (APPEARANCE_SPEC §6.3):
    /// 220 × 64, with `signatureImage` 220 × 110, with `stampImage` 240 × 147.5.
    public struct SignatureAppearance: Sendable, Equatable {
        /// Input document page, 1-based (an explicit number is kept as is); 0 = the input's last page that is not an eID
        /// verify page — neither this prepare's verify page nor earlier revisions' ones count (PLACEMENT_SPEC §1a).
        public var page: Int
        public var x: Double
        public var y: Double
        public var width: Double
        public var height: Double
        /// "mn" | "en"; nil → PrepareOptions.lang (nil → mn).
        public var lang: String?
        /// Draw the stamp exactly at page/x/y/width/height (a position the signer chose, e.g. dragged on a page
        /// preview): never moved off page content. `Placement.status` is then `.requested`, or `.overlap` when content
        /// is under the rect (`.unscanned` when the page cannot be scanned) — never `.moved`. false (default) = x/y is
        /// only the preferred spot (PLACEMENT_SPEC.md §6, §6a). The rect must lie inside the page (else REQUEST_INVALID).
        public var exact: Bool
        /// The signer's handwritten-signature image (CA: GET /v3/person/etsi/{etsi}/signature-image) drawn inside the
        /// stamp (APPEARANCE_SPEC.md §6). nil = none (byte-identical to golden v9).
        public var signatureImage: PdfImage?
        /// The organization's stamp image (CA: representations[].stampImage); only with `PrepareOptions.claimedRole`
        /// (onBehalfOf), REQUEST_INVALID otherwise. The round stamp overlaps the box top-right and sticks out above it —
        /// width/height are the whole widget rect (APPEARANCE_SPEC.md §6.3).
        public var stampImage: PdfImage?

        public init(page: Int = 0, x: Double, y: Double, width: Double = 0, height: Double = 0, lang: String? = nil,
                    exact: Bool = false, signatureImage: PdfImage? = nil, stampImage: PdfImage? = nil) {
            self.page = page
            self.x = x
            self.y = y
            self.width = width
            self.height = height
            self.lang = lang
            self.exact = exact
            self.signatureImage = signatureImage
            self.stampImage = stampImage
        }
    }

    /// A "PDF image" as the CA serves it (Go `pades.PDFImage`, APPEARANCE_SPEC.md §6.1): one ink colour + an 8-bit alpha
    /// channel. The SDK writes `alpha` into the PDF verbatim (/SMask, /FlateDecode) — nothing is compressed at runtime.
    /// Decodable from the CA JSON `{width, height, color, alpha (base64), sha256}`.
    public struct PdfImage: Sendable, Equatable, Codable {
        /// px, 1…1600.
        public var width: Int
        public var height: Int
        /// [r, g, b], 0…255.
        public var color: [Int]
        /// zlib stream (RFC 1950, no preset dictionary, nothing after the Adler-32) inflating to exactly width·height
        /// bytes, rows top-down, no PNG filter bytes; ≤ 300 KiB. JSON: base64.
        public var alpha: Data
        /// Lowercase hex SHA-256 of the PNG the CA stores; not written into the PDF, carried to the registration
        /// (`Completed.images` → `images`).
        public var sha256: String

        public init(width: Int, height: Int, color: [Int], alpha: Data, sha256: String) {
            self.width = width
            self.height = height
            self.color = color
            self.alpha = alpha
            self.sha256 = sha256
        }

        var core: Appearance.Image { Appearance.Image(w: width, h: height, color: color, alpha: [UInt8](alpha)) }
    }

    /// One image drawn in a signature's stamp (Go `eid.PDFSignatureImage`): `Completed.images`, registration `images`.
    public struct SignatureImage: Sendable, Equatable, Codable {
        public enum Kind: String, Sendable, Codable {
            /// The citizen's handwritten-signature image.
            case signature
            /// The organization's stamp image.
            case stamp
        }
        public let kind: Kind
        /// SHA-256 (64 lowercase hex) of the PNG the CA stores.
        public let sha256: String
    }

    /// Default stamp sizes (pt) when `SignatureAppearance.width` and `height` are both 0 (APPEARANCE_SPEC.md §6.3).
    public static let defaultStampSize = (width: 220.0, height: 64.0)
    public static let defaultSignatureStampSize = (width: 220.0, height: 110.0)
    public static let defaultOrgStampSize = (width: 240.0, height: 147.5)

    /// Go `appearanceSize`: width/height, or the default for the images when both are 0.
    static func appearanceSize(_ a: SignatureAppearance) -> (width: Double, height: Double) {
        if a.width != 0 || a.height != 0 { return (a.width, a.height) }
        if a.stampImage != nil { return defaultOrgStampSize }
        if a.signatureImage != nil { return defaultSignatureStampSize }
        return defaultStampSize
    }

    public struct Prepared: Sendable, Equatable {
        /// SHA-256(signedAttrs) — what the phone/token signs (32 bytes).
        public let dtbs: Data
        /// messageDigest = SHA-256(ByteRange).
        public let digest: Data
        public let docId: String
        /// Opaque; may be persisted while waiting for the signature.
        public let state: Data
        /// Where the visible stamp was drawn; nil without `appearance` (PLACEMENT_SPEC.md).
        public let placement: Placement?
    }

    /// The visible stamp's final rect (`SignatureAppearance` coordinates, pt) and how it was chosen (Go
    /// `pades.Placement`, Android `Placement`). The stamp avoids existing page content (PLACEMENT_SPEC.md): `.requested`
    /// = drawn at appearance x/y; `.moved` = that spot was occupied and the stamp moved to free space; `.overlap` = no
    /// free spot, drawn at the requested spot over content; `.unscanned` = the page could not be scanned within the
    /// limits, drawn at the requested spot. Surface `.overlap` / `.unscanned` to the signer — the signature is valid
    /// either way.
    public struct Placement: Sendable, Equatable {
        public enum Status: String, Sendable {
            case requested, moved, overlap, unscanned
        }
        /// 1-based page the stamp is on.
        public let page: Int
        public let x: Double
        public let y: Double
        public let width: Double
        public let height: Double
        public let status: Status
    }

    /// `suggestPlacement` result (Go `pades.Suggestion`, Android `PlacementSuggestion`, PLACEMENT_SPEC.md §6b), pt.
    /// `page`, `x`, `y`, `width`, `height`, `status` are what `prepare` returns in `Prepared.placement` for the same PDF
    /// and appearance. Coordinates: origin at the visible lower-left corner, x right, y up — a UI that renders the page
    /// at `s` px/pt with a top-left origin maps `left = x·s`, `top = (pageHeight − y − height)·s`; back: `x = left/s`,
    /// `y = pageHeight − top/s − height`, then prepare with `exact: true`.
    public struct PlacementSuggestion: Sendable, Equatable {
        /// A page's visible size (CropBox, else MediaBox, after /Rotate), pt; (0, 0) = geometry unreadable.
        public struct PageSize: Sendable, Equatable {
            public let width: Double
            public let height: Double
        }
        /// 1-based page, resolved (appearance page 0 → PLACEMENT_SPEC §1a).
        public let page: Int
        public let x: Double
        public let y: Double
        public let width: Double
        public let height: Double
        public let status: Placement.Status
        /// Visible size of `page`.
        public let pageWidth: Double
        public let pageHeight: Double
        /// Pages in /Pages tree order.
        public let pageCount: Int
        /// Visible size of every page; index 0 = page 1.
        public let pages: [PageSize]
    }

    public struct CompleteOptions: Sendable {
        /// RFC 3161 TSA. nil → https://tsa.timeserver.mn/.
        public var tsaUrl: String?
        /// Trust anchors DER (TSA chain). nil → Mongolian National Root CA. Tests/sandbox only.
        public var roots: [Data]?
        /// HTTP for TSA/OCSP/CRL. nil → URLSession (10 s, no redirects).
        public var transport: EidPadesTransport?

        /// Test hooks (golden vectors): clock, sleep and TSA nonce source.
        var now: (@Sendable () -> Date)?
        var sleep: (@Sendable (TimeInterval) async throws -> Void)?
        var nonce: (@Sendable () -> [UInt8])?

        public init(tsaUrl: String? = nil, roots: [Data]? = nil, transport: EidPadesTransport? = nil) {
            self.tsaUrl = tsaUrl
            self.roots = roots
            self.transport = transport
        }
    }

    /// Signed document + the values the CA registry needs: `registration(medium:sessionId:onBehalfOf:)` builds the
    /// body the RP backend posts to `POST /pdf/signatures` (Go `pades.Registration` → `Client.PDF.RegisterSignature`,
    /// TS `registrationFromCompleted` → `registerSignature`).
    public struct Completed: Sendable, Equatable {
        public let pdf: Data
        /// CMS DER embedded in /Contents.
        public let cms: Data
        public let docId: String
        /// SHA-256 of `pdf` (with the DSS revision), lower hex.
        public let outSha256: String
        /// SHA-256 of the prepare input, lower hex.
        public let inSha256: String
        /// A verification page was appended before this signature.
        public let hasPage: Bool
        /// SHA-256 of the document after the page (before the signature revision); nil without a page.
        public let pageSha256: String?
        /// This signature's number in the document (1…16).
        public let revIndex: Int
        /// SHA-256 of the signature revision (before the DSS revision), lower hex.
        public let sigRevSha256: String
        /// SHA-256 of each prior signature's CMS DER, in document order.
        public let priorCmsSha256: [String]
        /// SHA-256 of each prior signature's revision (`doc[0 : ByteRange[2]+ByteRange[3]]`), same order as
        /// `priorCmsSha256` — how the CA identifies a prior CA-assembled (mode A) row (`priorRevisionSha256`).
        public let priorRevisionSha256: [String]
        /// Citizen SIGN certificate (DER).
        public let signerCert: Data
        /// `PrepareOptions.fileName` as cleaned by prepare (CA `cleanFileName`); nil when not given or invalid.
        public let fileName: String?
        /// `PrepareOptions.claimedRole` carried through the state; nil when the signature is personal. `registration`
        /// requires `onBehalfOf` when this is set (the CA rejects a claimed role without an organisation).
        public var claimedRole: String? = nil
        /// The images drawn in this signature's stamp (`signatureImage`, then `stampImage`) as {kind, sha256};
        /// `registration` sends them as `images` (APPEARANCE_SPEC.md §6.6). Empty without images.
        public var images: [SignatureImage] = []
    }

    // MARK: - prepare

    /// Writes the signature revision (fixed placeholder) and returns the DTBS. No network.
    public static func prepare(pdf: Data, options o: PrepareOptions) throws -> Prepared {
        let doc = [UInt8](pdf)
        guard doc.count <= maxInputBytes else { throw EidPadesError(code: .pdfTooLarge, message: "PDF exceeds 9.75 MB") }
        guard doc.starts(with: Array("%PDF-".utf8)) else { throw EidPadesError(code: .pdfInvalid, message: "not a PDF") }
        do { try Structure.check(doc) } catch {
            throw EidPadesError(code: .pdfInvalid, message: "PDF structure nested too deep or too complex")
        }
        let cert: X509Cert
        do { cert = try X509Cert(der: [UInt8](o.signerCert)) } catch {
            throw EidPadesError(code: .signerInvalid, message: "signerCert: \(error)")
        }
        guard cert.isRSA || cert.isEC else { throw EidPadesError(code: .signerInvalid, message: "unsupported key type") }
        let chain = try signerChain(cert, o.chain)
        if let id = o.docId, !id.isEmpty, !isUUID(id) {
            throw EidPadesError(code: .requestInvalid, message: "docId must be a lower-case UUID")
        }
        if let l = o.lang, !l.isEmpty, l != "mn", l != "en" {
            throw EidPadesError(code: .requestInvalid, message: "lang: mn | en")
        }
        if let p = o.verifyPagePosition, !p.isEmpty, p != "last", p != "first" {
            throw EidPadesError(code: .requestInvalid, message: "verifyPagePosition: last | first")
        }
        let first = o.verifyPagePosition == "first"
        try checkAppearance(o)
        if o.appearance?.stampImage != nil, o.claimedRole?.isEmpty ?? true {
            throw EidPadesError(code: .requestInvalid, message: "appearance: stampImage only with claimedRole (onBehalfOf)")
        }
        let now = o.signingTime ?? Date()
        let inHex = Crypto.hex(Crypto.sha256(doc))
        let fileName = cleanFileName(o.fileName ?? "")

        let (newDoc, revIndex) = try Prechecks.inspect(doc, issuers: EidChain.issuers + [chain[0]])
        var docID = o.docId ?? ""
        if !newDoc, let fromPage = Prechecks.docIDFromPage(doc) {
            if !docID.isEmpty, docID != fromPage {
                throw EidPadesError(code: .requestInvalid, message: "docId differs from the document's page")
            }
            docID = fromPage
        }
        if newDoc, docID.isEmpty {
            do { docID = try randomUUID() } catch { throw EidPadesError(code: .internal, message: "uuid: \(error)") }
        }
        let hasPage = newDoc && o.verifyPage
        var base = doc
        var pageHex = ""
        if hasPage {
            guard let fileName else {
                throw EidPadesError(code: .requestInvalid, message: "fileName required, ≤ 120 characters")
            }
            do {
                base = try VerifyPage.append(doc, VerifyPage.Data(
                    brand: "eID Mongolia", fileName: fileName, documentHash: inHex, fileSize: doc.count, docId: docID,
                    verifyURL: Prechecks.verifyURLPrefix + docID, trustURL: "https://eidmongolia.mn/trust",
                    caName: cert.issuerCommonName, tsaName: "eID Mongolia TSA (tsa.timeserver.mn)", provider: "ca.eidmongolia.mn",
                    lang: o.lang ?? ""), first: first)
            } catch {
                throw EidPadesError(code: .pdfInvalid, message: "could not append the verification page: \(error)")
            }
            pageHex = Crypto.hex(Crypto.sha256(base))
        }
        var name = o.signerName ?? ""
        if name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { name = CMS.signerDisplayName(cert) }
        let visible = try o.appearance.map { try visibleSpec(doc, $0, o, name: name, now: now, docID: docID, revIndex: revIndex) }
        // visible.page counts the input's pages; a verify page added in front shifts them by one in base (PLACEMENT_SPEC §1b).
        var onBase = visible
        if hasPage, first { onBase?.page += 1 }
        let prep: PadesSignature.Prepared
        do {
            prep = try PadesSignature.prepare(base, signingTime: now, timeZone: signingTimeZone, signerName: name,
                                              reason: o.reason ?? "", visible: onBase)
        } catch let e as Appearance.Failure {
            throw EidPadesError(code: .requestInvalid, message: "appearance: \(e)")
        } catch {
            throw EidPadesError(code: .pdfInvalid, message: "could not write the signature revision: \(error)")
        }
        guard prep.pdf.count + (256 << 10) <= maxOutputBytes else {
            throw EidPadesError(code: .pdfTooLarge, message: "signed output would exceed 10 MB")
        }
        let attrs: [UInt8]
        do {
            attrs = try CMS.signedAttributes(messageDigest: prep.digest, signer: cert, claimedRole: o.claimedRole ?? "")
        } catch {
            throw EidPadesError(code: .requestInvalid, message: "claimedRole: \(error)")
        }
        let st = State(docId: docID, signerCert: cert.raw, chain: chain.map(\.raw), signedAttrs: attrs,
                       byteRange: prep.byteRange, revIndex: revIndex, inSha256: inHex, hasPage: hasPage,
                       pageSha256: pageHex.isEmpty ? nil : pageHex, claimedRole: o.claimedRole?.nilIfEmpty,
                       fileName: fileName, preparedSha256: Crypto.hex(Crypto.sha256(prep.pdf)), pdf: prep.pdf,
                       images: imageRefs(o.appearance))
        var placement: Placement?
        if let vis = visible, let pl = prep.placement {
            placement = Placement(page: vis.page, x: Double(pl.x) / 100, y: Double(pl.y) / 100, width: Double(vis.w) / 100,
                                  height: Double(vis.h) / 100, status: Placement.Status(rawValue: pl.status.rawValue) ?? .unscanned)
        }
        return Prepared(dtbs: Data(CMS.dtbs(attrs)), digest: Data(prep.digest), docId: docID, state: Data(try st.encode()),
                        placement: placement)
    }

    // MARK: - suggestPlacement

    /// Runs `prepare`'s placement (page 0 resolution, page scan, candidate search; `appearance.exact`) on `pdf` without
    /// signing — no certificate, no network — so a UI can show the default stamp position, the page sizes, and whether a
    /// chosen rect lies over content (Go `pades.SuggestPlacement`, PLACEMENT_SPEC.md §6b).
    ///
    /// Checks, in order: size (PDF_TOO_LARGE), `%PDF-` header and structure (PDF_INVALID), appearance values
    /// (REQUEST_INVALID), encryption (PDF_ENCRYPTED), page > page count / page geometry / rect outside the page
    /// (REQUEST_INVALID). Not checked here (`prepare` does): prior signatures (PDF_FOREIGN_SIGNATURE…), the signer
    /// certificate, and whether the signer's name fits the stamp. Page 0 skips this document's eID verify pages using
    /// the docId read from its verify page — for an unsigned document no page is skipped.
    public static func suggestPlacement(pdf: Data, appearance a: SignatureAppearance) throws -> PlacementSuggestion {
        let doc = [UInt8](pdf)
        guard doc.count <= maxInputBytes else { throw EidPadesError(code: .pdfTooLarge, message: "PDF exceeds 9.75 MB") }
        guard doc.starts(with: Array("%PDF-".utf8)) else { throw EidPadesError(code: .pdfInvalid, message: "not a PDF") }
        do { try Structure.check(doc) } catch {
            throw EidPadesError(code: .pdfInvalid, message: "PDF structure nested too deep or too complex")
        }
        try checkAppearance(PrepareOptions(signerCert: Data(), appearance: a))
        let (r, _, sigs) = try Prechecks.open(doc)
        var verifyURI = ""
        if !sigs.isEmpty, let id = Prechecks.docIDFromPage(doc, reader: r) { verifyURI = Prechecks.verifyURLPrefix + id }
        let (aw, ah) = appearanceSize(a)
        let w = Appearance.round100(aw), h = Appearance.round100(ah)
        let s: (page: Int, result: StampPlacement.Result, sizes: [(w: Int, h: Int)?])
        do {
            s = try Appearance.suggest(doc, verifyURI: verifyURI, page: a.page, x: Appearance.round100(a.x),
                                       y: Appearance.round100(a.y), w: w, h: h, exact: a.exact)
        } catch let e as Appearance.Failure {
            throw EidPadesError(code: .requestInvalid, message: "appearance: \(e)")
        } catch {
            throw EidPadesError(code: .pdfInvalid, message: "PDF: \(error)")
        }
        let pages = s.sizes.map { PlacementSuggestion.PageSize(width: Double($0?.w ?? 0) / 100, height: Double($0?.h ?? 0) / 100) }
        return PlacementSuggestion(page: s.page, x: Double(s.result.x) / 100, y: Double(s.result.y) / 100,
                                   width: Double(w) / 100, height: Double(h) / 100,
                                   status: Placement.Status(rawValue: s.result.status.rawValue) ?? .unscanned,
                                   pageWidth: pages[s.page - 1].width, pageHeight: pages[s.page - 1].height,
                                   pageCount: pages.count, pages: pages)
    }

    // MARK: - complete

    /// Verifies the citizen signature over the DTBS → TSA → CMS → embed → OCSP/CRL after genTime → DSS revision.
    /// `signature`: RSA PKCS#1 v1.5, ECDSA raw r‖s (P-256 64 / P-384 96 bytes) or DER — by the certificate key.
    public static func complete(state: Data, signature: Data,
                                options o: CompleteOptions = CompleteOptions()) async throws -> Completed {
        let st: State
        do { st = try State.decode([UInt8](state)) } catch {
            throw EidPadesError(code: .stateInvalid, message: "state: \(error)")
        }
        do { try Structure.check(st.pdf) } catch {
            throw EidPadesError(code: .stateInvalid, message: "state PDF structure nested too deep or too complex")
        }
        let cert: X509Cert, chain: [X509Cert]
        do {
            cert = try X509Cert(der: st.signerCert)
            chain = try st.chain.map { try X509Cert(der: $0) }
        } catch {
            throw EidPadesError(code: .stateInvalid, message: "state certificates: \(error)")
        }
        let roots = try parseRoots(o.roots)
        let now: @Sendable () -> Date = o.now ?? { Date() }
        let sleep: @Sendable (TimeInterval) async throws -> Void = o.sleep ?? { try await Task.sleep(nanoseconds: UInt64($0 * 1e9)) }
        let dtbs = CMS.dtbs(st.signedAttrs)
        guard let sig = citizenSignature(cert, dtbs: dtbs, signature: [UInt8](signature)) else {
            throw EidPadesError(code: .signatureInvalid, message: "signature does not match the DTBS")
        }
        let f = Fetcher(o.transport ?? URLSessionPadesTransport())
        let ts: TSA.Token
        do {
            ts = try await TSA.timestamp(f, url: o.tsaUrl?.nilIfEmpty ?? TSA.defaultURL, signature: sig,
                                         nonce: o.nonce?() ?? randomBytes(8), roots: roots, intermediates: chain, now: now())
        } catch {
            throw EidPadesError(code: .tsaUnavailable, message: "TSA: \(error)")
        }
        let cms: [UInt8]
        do {
            cms = try CMS.assemble(signedAttrs: st.signedAttrs, signer: cert, chain: chain, signature: sig,
                                   timestampToken: ts.raw)
        } catch {
            throw EidPadesError(code: .selfValidationFailed, message: "CMS: \(error)")
        }
        let signed: [UInt8]
        do {
            signed = try PadesSignature.embed(st.pdf, byteRange: st.byteRange, cms: cms)
        } catch PadesSignature.Failure.placeholderOverflow(let n) {
            throw EidPadesError(code: .placeholderOverflow, message: "CMS \(n) bytes does not fit the placeholder")
        } catch {
            throw EidPadesError(code: .stateInvalid, message: "embed: \(error)")
        }
        var dss: PadesDSS.Material
        do {
            dss = try await LTV.collectWithWait(f, now: now, sleep: sleep, genTime: ts.genTime, roots: roots,
                                                chains: [[cert] + chain, ts.certificates])
        } catch let e as CertificateRevoked {
            throw EidPadesError(code: .ltvUnavailable, message: e.description, certificateRevoked: true)
        } catch {
            throw EidPadesError(code: .ltvUnavailable, message: "OCSP/CRL: \(error)")
        }
        let out: [UInt8]
        do {
            dss.contents = try PadesSignature.signatureContents(signed, byteRange: st.byteRange)
            out = try PadesDSS.append(signed, dss)
        } catch {
            throw EidPadesError(code: .selfValidationFailed, message: "DSS revision: \(error)")
        }
        guard out.count <= maxOutputBytes else { throw EidPadesError(code: .pdfTooLarge, message: "output exceeds 10 MiB") }
        let prior = try selfCheck(out, signed: signed, cms: cms, state: st)
        return Completed(pdf: Data(out), cms: Data(cms), docId: st.docId, outSha256: Crypto.hex(Crypto.sha256(out)),
                         inSha256: st.inSha256, hasPage: st.hasPage, pageSha256: st.pageSha256, revIndex: st.revIndex,
                         sigRevSha256: Crypto.hex(Crypto.sha256(signed)),
                         priorCmsSha256: prior.map { Crypto.hex(Crypto.sha256($0.cms)) },
                         priorRevisionSha256: prior.map { Crypto.hex(Crypto.sha256(Array(signed[0..<$0.end]))) },
                         signerCert: Data(cert.raw), fileName: st.fileName, claimedRole: st.claimedRole?.nilIfEmpty,
                         images: st.images)
    }

    /// Light self-check of the output (no full validator — Go runs the CA validator here): the document parses, its
    /// signature count is `revIndex`, the final Catalog has /DSS, and the new signature is the one prepared — same
    /// ByteRange, its /Contents is exactly `cms`, it covers the whole signature revision (`signed`, which `out`
    /// extends unchanged) and verifies (messageDigest over the ByteRange, signature over signedAttrs). Returns the
    /// prior signatures (CMS DER, revision end) in object order.
    static func selfCheck(_ out: [UInt8], signed: [UInt8], cms: [UInt8], state st: State) throws -> [(cms: [UInt8], end: Int)] {
        func fail(_ m: String) -> EidPadesError { EidPadesError(code: .selfValidationFailed, message: "output self-check: " + m) }
        guard out.count > signed.count, out.starts(with: signed), st.byteRange[2] + st.byteRange[3] == signed.count else {
            throw fail("the signature does not cover its revision")
        }
        let r: PdfReader
        do { r = try PdfReader(out) } catch { throw fail("output does not parse") }
        guard let root = (try? r.resolve(r.trailer["Root"]))?.dict, (try? r.resolve(root["DSS"]))?.dict != nil else {
            throw fail("no /DSS")
        }
        var prior: [(cms: [UInt8], end: Int)] = []
        var found = false
        var count = 0
        for d in Prechecks.signatureDicts(r) {
            if let t = (try? r.resolve(d["Type"]))?.nameValue, t != "Sig" { continue }
            count += 1
            guard let arr = (try? r.resolve(d["ByteRange"]))?.array else { throw fail("signature without /ByteRange") }
            let br = arr.compactMap { (try? r.resolve($0))?.intValue }.map(Int.init)
            if br == st.byteRange {
                guard !found, GeregeEIDPades.PriorSignature.contentsDER(out, br) == cms, GeregeEIDPades.PriorSignature(d, reader: r, doc: out) != nil else {
                    throw fail("the new signature does not verify")
                }
                found = true
            } else if let der = GeregeEIDPades.PriorSignature.contentsDER(out, br), br.count == 4, br[2] + br[3] <= out.count {
                prior.append((der, br[2] + br[3]))
            }
        }
        guard found, count == st.revIndex else { throw fail("signature count \(count), want \(st.revIndex)") }
        return prior
    }

    // MARK: - Helpers

    /// Appearance checks that do not need the PDF (Go `checkAppearance`, APPEARANCE_SPEC.md §1).
    static func checkAppearance(_ o: PrepareOptions) throws {
        guard let a = o.appearance else { return }
        func bad(_ m: String) -> EidPadesError { EidPadesError(code: .requestInvalid, message: "appearance: " + m) }
        for v in [a.x, a.y, a.width, a.height] where !v.isFinite || v < 0 || v > 14400 {
            throw bad("x, y, width, height must be 0…14400 pt")
        }
        guard a.page >= 0 else { throw bad("page ≥ 0") }
        if let l = a.lang, !l.isEmpty, l != "mn", l != "en" { throw bad("lang: mn | en") }
        if let role = o.claimedRole,
           role.unicodeScalars.contains(where: { [.control, .format].contains($0.properties.generalCategory) }) {
            throw bad("claimedRole contains control characters")
        }
        for (name, im) in [("signatureImage", a.signatureImage), ("stampImage", a.stampImage)] {
            guard let im else { continue }
            guard im.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw bad(name + ".sha256: lowercase hex SHA-256")
            }
            do { try Appearance.checkImage(im.core) } catch { throw bad(name + ": \(error)") }
        }
    }

    /// Completed.images (APPEARANCE_SPEC.md §6.6): signatureImage, then stampImage.
    static func imageRefs(_ a: SignatureAppearance?) -> [SignatureImage] {
        guard let a else { return [] }
        var out: [SignatureImage] = []
        if let im = a.signatureImage { out.append(SignatureImage(kind: .signature, sha256: im.sha256)) }
        if let im = a.stampImage { out.append(SignatureImage(kind: .stamp, sha256: im.sha256)) }
        return out
    }

    /// Go `visibleSpec`: page (0 → the last page that is not an eID verify page, PLACEMENT_SPEC §1a), h100, language, +08 date, verify URL.
    static func visibleSpec(_ doc: [UInt8], _ a: SignatureAppearance, _ o: PrepareOptions, name: String, now: Date,
                            docID: String, revIndex: Int) throws -> Appearance.Visible {
        guard !docID.isEmpty else {
            throw EidPadesError(code: .requestInvalid, message: "appearance: docId required (the document has no verify page)")
        }
        let last: Int, n: Int
        do { (last, n) = try Appearance.defaultStampPage(doc, verifyURI: Prechecks.verifyURLPrefix + docID) } catch {
            throw EidPadesError(code: .pdfInvalid, message: "PDF: \(error)")
        }
        let page = a.page == 0 ? last : a.page
        guard page <= n else { throw EidPadesError(code: .requestInvalid, message: "appearance: page \(page) > page count \(n)") }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 8 * 3600)
        f.dateFormat = "yyyy-MM-dd HH:mm"
        let (w, h) = appearanceSize(a)
        return Appearance.Visible(
            page: page, x: Appearance.round100(a.x), y: Appearance.round100(a.y),
            w: Appearance.round100(w), h: Appearance.round100(h),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines), role: o.claimedRole ?? "",
            lang: a.lang?.nilIfEmpty ?? o.lang?.nilIfEmpty ?? "mn",
            date: f.string(from: now) + " (+08)", url: Prechecks.verifyURLPrefix + docID + "/" + String(revIndex),
            exact: a.exact, sig: a.signatureImage?.core, stamp: a.stampImage?.core)
    }

    static func parseRoots(_ ders: [Data]?) throws -> [X509Cert] {
        guard let ders, !ders.isEmpty else { return [EidChain.nationalRoot] }
        do { return try ders.map { try X509Cert(der: [UInt8]($0)) } } catch {
            throw EidPadesError(code: .requestInvalid, message: "roots: \(error)")
        }
    }

    /// Given chain, or signer → issuer through the embedded 02–05 (root excluded).
    static func signerChain(_ signer: X509Cert, _ ders: [Data]?) throws -> [X509Cert] {
        if let ders, !ders.isEmpty {
            do { return try ders.map { try X509Cert(der: [UInt8]($0)) } } catch {
                throw EidPadesError(code: .signerInvalid, message: "chain: \(error)")
            }
        }
        let pool = EidChain.intermediates
        var chain: [X509Cert] = []
        var cur = signer
        for _ in 0...pool.count {
            guard let next = pool.first(where: { cur.isSigned(by: $0) }) else { break }
            chain.append(next)
            cur = next
        }
        guard !chain.isEmpty else {
            throw EidPadesError(code: .signerInvalid, message: "signer's issuer is not in the embedded eID chain — pass chain")
        }
        return chain
    }

    /// CMS form of the citizen signature: RSA as is; ECDSA as DER (raw r‖s converted). nil when it does not verify.
    static func citizenSignature(_ cert: X509Cert, dtbs: [UInt8], signature: [UInt8]) -> [UInt8]? {
        if cert.isRSA {
            return Crypto.verifyDigest(key: cert, digest: dtbs, signature: signature) ? signature : nil
        }
        guard cert.isEC else { return nil }
        let n = cert.ecFieldBytes
        if signature.count == 2 * n {
            let der = DERW.seq(DERW.uint(Array(signature[..<n])), DERW.uint(Array(signature[n...])))
            if Crypto.verifyDigest(key: cert, digest: dtbs, signature: der) { return der }
        }
        return Crypto.verifyDigest(key: cert, digest: dtbs, signature: signature) ? signature : nil
    }

    static func isUUID(_ s: String) -> Bool {
        s.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", options: .regularExpression) != nil
    }

    static func randomBytes(_ n: Int) throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        let rc = SecRandomCopyBytes(kSecRandomDefault, n, &b)
        guard rc == errSecSuccess else { throw DERError("SecRandomCopyBytes failed (\(rc))") }
        return b
    }

    static func randomUUID() throws -> String {
        var b = try randomBytes(16)
        b[6] = b[6] & 0x0F | 0x40
        b[8] = b[8] & 0x3F | 0x80
        let h = Crypto.hex(b)
        let c = Array(h)
        return String(c[0..<8]) + "-" + String(c[8..<12]) + "-" + String(c[12..<16]) + "-" + String(c[16..<20]) + "-" + String(c[20...])
    }

    /// Go `cleanFileName`: drops Cc/Cf/Zl/Zp, NFC, trim; 1…120 characters.
    static func cleanFileName(_ s: String) -> String? {
        var out = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            switch u.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator: continue
            default: out.append(u)
            }
        }
        let t = String(out).precomposedStringWithCanonicalMapping.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.unicodeScalars.count <= maxFileName else { return nil }
        return t
    }
}

import Security

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
