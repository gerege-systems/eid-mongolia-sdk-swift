import CryptoKit
import Foundation

/// Signature revision writer (the PDF never leaves the device). 1:1 port of the Go reference
/// `pades/internal/core/signature.go` (taken from eid-mongolia-desktop f1babff, verified byte-identical):
/// prepare (signature revision + fixed placeholder) → messageDigest → CMS → embed → append DSS.
enum PadesSignature {
    /// /Contents capacity in binary CMS bytes (2× hex chars in the file) — CA `PlaceholderBytes` (2 × 14 KiB measured).
    static let placeholderBytes = 2 * (14 << 10)
    /// SubFilter of our citizen signatures (PAdES baseline).
    static let subFilter = "ETSI.CAdES.detached"
    /// /Reason limit in UTF-16 units (BOM + 2×127 = 256 bytes = the CA validator's ownText limit).
    static let reasonMaxUnits = 127
    /// Fixed-width field after "/ByteRange " ("[0 a b c]" + spaces).
    static let byteRangeWidth = 40

    enum Failure: Error, Equatable {
        /// The CMS does not fit the placeholder (CA `PLACEHOLDER_OVERFLOW`) — never truncated.
        case placeholderOverflow(Int)
        /// ByteRange / placeholder do not match the prepared document.
        case byteRangeMismatch
        case emptyCMS
        case alreadyFilled
        /// DocMDP P=1: no changes (signatures included) permitted.
        case locked
    }

    struct Prepared {
        let pdf: [UInt8]
        /// [0, a, b, c]: a = offset of '<', b = offset after '>', c = up to the end.
        let byteRange: [Int]
        /// SHA-256(PDF[0:a] ‖ PDF[b:b+c]) — the CMS messageDigest.
        let digest: [UInt8]
        /// The new field's /T ("Signature k").
        let fieldName: String
        /// The visible stamp's final position (nil for an invisible signature) — PLACEMENT_SPEC.md.
        var placement: StampPlacement.Result? = nil
    }

    /// Writes an invisible approval signature revision after `base`: /Sig dictionary with a zeroed placeholder,
    /// field + widget (added to the first page's /Annots), new Catalog + AcroForm (/SigFlags 3). `signerName`
    /// → /Name, `reason` (on behalf of an organisation: «<org>-ийг төлөөлж») → /Reason; both optional.
    /// `visible` (APPEARANCE_SPEC.md): the widget gets a /Rect on `visible.page`, /F 4 and an /AP /N form XObject
    /// (+ 2 fonts) and joins that page's /Annots; /Name must be written (else `Appearance.Failure`).
    static func prepare(_ base: [UInt8], signingTime: Date, timeZone: TimeZone,
                        signerName: String = "", reason: String = "", visible: Appearance.Visible? = nil) throws -> Prepared {
        let inc = try PdfIncremental(base)
        let r = inc.reader
        let root = inc.root
        let acroObj = try r.resolve(root["AcroForm"])
        let acro = acroObj.dict ?? PdfDict()
        let fields = try r.resolve(acro["Fields"]).array ?? []
        var names = Set<String>()
        var sigFields = 0
        for f in fields {
            let fd = try r.resolve(f).dict ?? PdfDict()
            names.insert(try r.resolve(fd["T"]).text)
            if try r.resolve(fd["FT"]).nameValue == "Sig" { sigFields += 1 }
        }
        var k = sigFields + 1
        while names.contains("Signature \(k)") { k += 1 }
        let fieldName = "Signature \(k)"

        let sigID = inc.reserve(), fieldID = inc.reserve(), catID = inc.reserve()
        // Visible: form, F1 ×5, F2 ×5.
        let apIDs = visible == nil ? [] : (0..<11).map { _ in inc.reserve() }

        // ── /Sig dictionary (placeholder) ──
        var sig = "<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /\(subFilter)\n /ByteRange "
        let brAt = sig.utf8.count
        sig += String(repeating: " ", count: byteRangeWidth)
        sig += "\n /Contents <"
        let contentsAt = sig.utf8.count - 1
        sig += String(repeating: "0", count: 2 * placeholderBytes)
        sig += ">\n /M " + pdfDate(signingTime, timeZone)
        let nameHex = text(signerName, maxUnits: 120)
        if let n = nameHex { sig += "\n /Name " + n }
        if let t = text(reason, maxUnits: reasonMaxUnits) { sig += "\n /Reason " + t }
        sig += "\n>>"
        let sigStart = inc.writeObject(sigID, Array(sig.utf8))

        // ── field + widget ──
        let page: Page?
        var placement: StampPlacement.Result?
        if let vis = visible {
            guard nameHex != nil, signerName.trimmingCharacters(in: .whitespacesAndNewlines) == vis.name else {
                throw Appearance.Failure("/Name would not be written")
            }
            guard let p = try Appearance.nthPage(r, root["Pages"], vis.page) else { throw Appearance.Failure("page \(vis.page) missing") }
            let (box, rot) = try Appearance.geometry(r, p.dict)
            var rect = try Appearance.rect(box: box, rot: rot, x: vis.x, y: vis.y, w: vis.w, h: vis.h)
            // PLACEMENT_SPEC.md: move off existing page content; the requested rect stays when nothing is free.
            let placed = StampPlacement.choose(r, page: p.dict, pageID: p.ref.id, box: box, rot: rot,
                                          x: vis.x, y: vis.y, w: vis.w, h: vis.h)
            if placed.status == .moved {
                rect = try Appearance.rect(box: box, rot: rot, x: placed.x, y: placed.y, w: vis.w, h: vis.h)
            }
            placement = placed
            let bodies = try Appearance.objects(Appearance.Params(w: vis.w, h: vis.h, rotate: rot, name: vis.name, role: vis.role,
                                                                  lang: vis.lang, date: vis.date, url: vis.url), ids: apIDs)
            inc.writeObject(fieldID, Appearance.widget(fieldName: fieldName, rect: rect, page: p.ref, sigID: sigID, formID: apIDs[0]))
            for (i, b) in bodies.enumerated() { inc.writeObject(apIDs[i], b) }
            page = p
        } else {
            // Invisible (digitorus createVisualSignature): first page.
            var fld = "<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n"
            page = try firstPage(r, root["Pages"], depth: 0)
            if let page { fld += "  /P \(page.ref.id) \(page.ref.gen) R\n" }
            fld += "  /F 132\n  /FT /Sig\n  /T (\(fieldName))\n  /V \(sigID) 0 R\n>>"
            inc.writeObject(fieldID, Array(fld.utf8))
        }
        if let page { try addWidget(inc, page: page, widget: fieldID) }

        // ── new Catalog ──
        var cat = "<<\n  /Type /Catalog\n"
        if root["Version"].isNull, let v = Double(r.version), v < 1.5 { cat += "  /Version /1.5\n" }
        cat += try inc.catalogCopy(skip: ["AcroForm"])
        cat += "  /AcroForm <<"
        if case .dict = acroObj {
            for key in acro.sortedKeys where key != "Fields" && key != "SigFlags" {
                cat += " /" + PdfIncremental.escapeName(key) + " " + (try inc.serialize(acro[key]))
            }
        }
        cat += " /Fields ["
        for f in fields { cat += try inc.serialize(f) + " " }
        cat += "\(fieldID) 0 R] /SigFlags 3 >>\n>>"
        inc.writeObject(catID, Array(cat.utf8))

        var doc = try inc.finish(rootID: catID)
        let a = sigStart + contentsAt
        let b = a + 2 * placeholderBytes + 2
        guard doc[a] == 0x3C, doc[b - 1] == 0x3E else { throw Failure.byteRangeMismatch }
        let br = [0, a, b, doc.count - b]
        let field = "[\(br[0]) \(br[1]) \(br[2]) \(br[3])]"
        guard field.utf8.count <= byteRangeWidth else { throw Failure.byteRangeMismatch }
        doc.replaceSubrange((sigStart + brAt)..<(sigStart + brAt + field.utf8.count), with: Array(field.utf8))
        return Prepared(pdf: doc, byteRange: br, digest: digest(doc, br), fieldName: fieldName, placement: placement)
    }

    /// SHA-256 over the two ByteRange spans.
    static func digest(_ doc: [UInt8], _ br: [Int]) -> [UInt8] {
        var h = SHA256()
        h.update(data: doc[br[0]..<(br[0] + br[1])])
        h.update(data: doc[br[2]..<(br[2] + br[3])])
        return Array(h.finalize())
    }

    /// Writes `cms` as hex into the placeholder; all other bytes unchanged. Never truncates.
    static func embed(_ prepared: [UInt8], byteRange br: [Int], cms: [UInt8]) throws -> [UInt8] {
        guard !cms.isEmpty else { throw Failure.emptyCMS }
        guard cms.count <= placeholderBytes else { throw Failure.placeholderOverflow(cms.count) }
        guard br.count == 4 else { throw Failure.byteRangeMismatch }
        let a = br[1], b = br[2]
        guard br[0] == 0, a > 0, b == a + 2 * placeholderBytes + 2, b + br[3] == prepared.count,
              prepared[a] == 0x3C, prepared[b - 1] == 0x3E else { throw Failure.byteRangeMismatch }
        guard prepared[(a + 1)..<(b - 1)].allSatisfy({ $0 == 0x30 }) else { throw Failure.alreadyFilled }
        var out = prepared
        let hex = Array("0123456789abcdef".utf8)
        var p = a + 1
        for byte in cms {
            out[p] = hex[Int(byte >> 4)]
            out[p + 1] = hex[Int(byte & 0x0F)]
            p += 2
        }
        return out
    }

    /// The /Contents value the ByteRange points at, hex-decoded with the zero padding (the bytes a viewer reads) —
    /// the DSS VRI key input.
    static func signatureContents(_ signed: [UInt8], byteRange br: [Int]) throws -> [UInt8] {
        guard br.count == 4 else { throw Failure.byteRangeMismatch }
        let a = br[1], b = br[2]
        guard br[0] == 0, a > 0, b > a + 2, b <= signed.count, signed[a] == 0x3C, signed[b - 1] == 0x3E,
              (b - a - 2) % 2 == 0 else { throw Failure.byteRangeMismatch }
        var out = [UInt8]()
        out.reserveCapacity((b - a - 2) / 2)
        var i = a + 1
        while i < b - 1 {
            guard let hi = PdfLexer.hexVal(signed[i]), let lo = PdfLexer.hexVal(signed[i + 1]) else {
                throw Failure.byteRangeMismatch
            }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    // MARK: - Helpers

    /// DocMDP with P=1 (no changes permitted) — signing would invalidate the certifying signature.
    static func isLocked(_ r: PdfReader, _ root: PdfDict) throws -> Bool {
        guard let perms = try r.resolve(root["Perms"]).dict, let sig = try r.resolve(perms["DocMDP"]).dict else { return false }
        for ref in try r.resolve(sig["Reference"]).array ?? [] {
            guard let rd = try r.resolve(ref).dict, try r.resolve(rd["TransformMethod"]).nameValue == "DocMDP" else { continue }
            let p = try r.resolve(r.resolve(rd["TransformParams"]).dict?["P"] ?? .null).intValue ?? 2
            if p == 1 { return true }
        }
        return false
    }

    struct Page { let ref: PdfRef; let dict: PdfDict }

    /// First /Page of the /Pages tree (depth-bounded, digitorus findFirstPage).
    private static func firstPage(_ r: PdfReader, _ node: PdfObject, depth: Int) throws -> Page? {
        guard depth <= 32, let ref = node.refValue, let d = try r.resolve(node).dict else { return nil }
        switch try r.resolve(d["Type"]).nameValue {
        case "Page": return Page(ref: ref, dict: d)
        case "Pages":
            for kid in try r.resolve(d["Kids"]).array ?? [] {
                if let p = try firstPage(r, kid, depth: depth + 1) { return p }
            }
        default: break
        }
        return nil
    }

    /// Appends the widget to the page's /Annots: rewrites an indirect /Annots array in place, else the page
    /// itself (same number/generation, other keys unchanged).
    private static func addWidget(_ inc: PdfIncremental, page: Page, widget: Int) throws {
        let raw = page.dict["Annots"]
        let annots = try inc.reader.resolve(raw)
        if !annots.isNull, annots.array == nil { throw PdfError("page /Annots is not an array") }
        var arr = "["
        for e in annots.array ?? [] { arr += try inc.serialize(e) + " " }
        arr += "\(widget) 0 R]"
        if let ref = raw.refValue, !annots.isNull {
            inc.writeObject(ref.id, gen: ref.gen, Array(arr.utf8))
            return
        }
        var s = "<<"
        for key in page.dict.sortedKeys where key != "Annots" {
            s += " /" + PdfIncremental.escapeName(key) + " " + (try inc.serialize(page.dict[key]))
        }
        s += " /Annots " + arr + " >>"
        inc.writeObject(page.ref.id, gen: page.ref.gen, Array(s.utf8))
    }

    /// PDF text string (hex): ASCII as is, else UTF-16BE with BOM. nil (not written) for empty, too long
    /// (`maxUnits` UTF-16 units), control characters or PDF keywords (CA validator ownText).
    static func text(_ s: String, maxUnits: Int) -> String? {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.utf16.count <= maxUnits else { return nil }
        var ascii = true
        for u in t.unicodeScalars {
            if u.value < 0x20 || u.value == 0x7F || u.properties.generalCategory == .control { return nil }
            if u.value > 0x7E { ascii = false }
        }
        for bad in [" obj", "endobj", "stream", "xref", "trailer", "%%EOF"] where t.contains(bad) { return nil }
        if ascii { return PdfIncremental.hexString(Array(t.utf8)) }
        var raw: [UInt8] = [0xFE, 0xFF]
        for u in t.utf16 { raw += [UInt8(u >> 8), UInt8(u & 0xFF)] }
        return PdfIncremental.hexString(raw)
    }

    /// "(D:YYYYMMDDHHmmSS+HH'mm')" in `zone` (digitorus pdfDateTime).
    static func pdfDate(_ t: Date, _ zone: TimeZone) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = zone
        f.dateFormat = "yyyyMMddHHmmss"
        var off = zone.secondsFromGMT(for: t)
        var sign = "+"
        if off < 0 { sign = "-"; off = -off }
        return String(format: "(D:%@%@%02d'%02d')", f.string(from: t), sign, off / 3600, (off % 3600) / 60)
    }
}
