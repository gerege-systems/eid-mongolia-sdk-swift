import Foundation

/// Verification (QR) page — PAGE_SPEC.md (pades-client/1), 1:1 port of the Go reference
/// `pades/internal/core/vpage.go`. Deterministic: integer coordinates, fixed colour strings, uncompressed content,
/// QR as vector rectangles; the only filtered bytes are the fixed font assets.
enum VerifyPage {
    struct Data {
        var brand: String
        var fileName: String
        var documentHash: String
        var fileSize: Int
        var docId: String
        var verifyURL: String
        var trustURL: String
        var caName: String
        var tsaName: String
        var provider: String
        /// "mn" (default, empty) | "en" — PAGE_SPEC §3a.
        var lang: String
    }

    /// PAGE_SPEC §3a texts (Go reference `pageTexts`, golden v2). Exact code points (NFC).
    struct Texts {
        let title, subtitle, document, fileName, hashAlg, size, docHash, docID, verification: String
        let scan, scanHint, trust, provider: String
    }

    static let texts: [String: Texts] = [
        "mn": Texts(
            title: "-аар гарын үсэг зурсан баримт",
            subtitle: "Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.",
            document: "БАРИМТ", fileName: "БАРИМТЫН НЭР", hashAlg: "HASH АЛГОРИТМ", size: "ХЭМЖЭЭ",
            docHash: "БАРИМТЫН HASH", docID: "БАРИМТЫН ID", verification: "ШАЛГАХ",
            scan: "Гарын үсгийг шалгах",
            scanHint: "QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.",
            trust: "Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:",
            provider: "Үйлчилгээ"),
        "en": Texts(
            title: " — Electronically signed document",
            subtitle: "Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.",
            document: "DOCUMENT", fileName: "FILE NAME", hashAlg: "HASH ALGORITHM", size: "SIZE",
            docHash: "DOCUMENT HASH", docID: "DOCUMENT ID", verification: "VERIFICATION",
            scan: "Scan to verify",
            scanHint: "Scan this QR code with your phone camera to verify.",
            trust: "Adobe Acrobat: trust the Mongolian National Root CA",
            provider: "Provider"),
    ]

    struct Font {
        let psName: String
        let stream: [UInt8]
        let length1: Int
        let ascent: Int
        let descent: Int
        let capHeight: Int
        let bbox: [Int]
        let widths: [Int]
        let gid: [UInt32: Int]

        private struct Metrics: Decodable {
            var psName: String
            var length1: Int
            var ascent: Int
            var descent: Int
            var capHeight: Int
            var bbox: [Int]
            var widths: [Int]
            var cmap: [[UInt32]]
        }

        static func load(_ name: String) throws -> Font {
            guard let dir = Bundle.module.url(forResource: "fonts", withExtension: nil) else { throw DERError("font assets missing") }
            let m = try JSONDecoder().decode(Metrics.self, from: Foundation.Data(contentsOf: dir.appendingPathComponent("\(name).metrics.json")))
            let stream = [UInt8](try Foundation.Data(contentsOf: dir.appendingPathComponent("\(name).ttf.zlib")))
            var gid: [UInt32: Int] = [:]
            for p in m.cmap where p.count == 2 { gid[p[0]] = Int(p[1]) }
            return Font(psName: m.psName, stream: stream, length1: m.length1, ascent: m.ascent, descent: m.descent,
                        capHeight: m.capHeight, bbox: m.bbox, widths: m.widths, gid: gid)
        }

        static let regular = Result { try load("NotoSans-Regular") }
        static let bold = Result { try load("NotoSans-Bold") }
    }

    static let mediaBox = "[0 0 595.28 841.89]"
    static let left = 42, width = 510, col2 = 297, qrModule = 2, qrTextX = 136, fileNameMax = 3
    static let colText = "0.118 0.118 0.118", colMuted = "0.431 0.431 0.431", colOK = "0.086 0.541 0.31"
    static let colBanner = "0.863 0.961 0.902", colLine = "0.863 0.863 0.863", colLink = "0.118 0.431 0.863"
    static let bannerPath = "48 800 m\n546 800 l\n549.31 800 552 797.31 552 794 c\n552 754 l\n552 750.69 549.31 748 546 748 c\n" +
        "48 748 l\n44.69 748 42 750.69 42 754 c\n42 794 l\n42 797.31 44.69 800 48 800 c\nh\nf"

    struct Link { let x1, y1, x2, y2: Int; let url: String }

    final class Writer {
        var ops = ""
        let reg: Font, bld: Font
        var links: [Link] = []

        init(reg: Font, bld: Font) { self.reg = reg; self.bld = bld }

        func op(_ s: String) { ops += s + "\n" }
        func font(_ id: Int) -> Font { id == 2 ? bld : reg }

        func gids(_ id: Int, _ s: String) -> [Int] {
            let f = font(id)
            return s.unicodeScalars.map { f.gid[$0.value] ?? f.gid[0x3F] ?? 0 }
        }

        func width1000(_ id: Int, _ size: Int, _ s: String) -> Int {
            if id == 3 { return 600 * s.unicodeScalars.count * size }
            let f = font(id)
            return gids(id, s).reduce(0) { $0 + (f.widths.indices.contains($1) ? f.widths[$1] : 0) } * size
        }

        func text(_ id: Int, _ size: Int, _ x: Int, _ y: Int, _ color: String, _ s: String) {
            let str: String
            if id == 3 {
                str = "(" + VerifyPage.literal(s) + ")"
            } else {
                str = glyphHex(id, s)
            }
            op("\(color) rg")
            op("BT /F\(id) \(size) Tf \(x) \(y) Td \(str) Tj ET")
        }

        /// F1/F2 text as `<GGGG…>` (PAGE_SPEC §2).
        func glyphHex(_ id: Int, _ s: String) -> String {
            "<" + gids(id, s).map { String(format: "%04X", UInt32($0)) }.joined() + ">"
        }

        func link(_ id: Int, _ size: Int, _ x: Int, _ y: Int, _ s: String) {
            let wd = (width1000(id, size, s) + 999) / 1000
            links.append(Link(x1: x, y1: y - 3, x2: x + wd, y2: y + size, url: s))
        }

        func hline(_ y: Int) {
            op("\(colLine) RG")
            op("0.75 w \(left) \(y) m \(left + width) \(y) l S")
        }

        /// PAGE_SPEC §4.
        func wrap(_ id: Int, _ size: Int, _ s: String, maxW: Int, maxLines: Int) -> [String] {
            wrapLimit(id, size, s, limit: maxW * 1000, maxLines: maxLines)
        }

        /// wrap with the width limit in 1/1000 pt (visible appearance: 1/100 pt × 10).
        func wrapLimit(_ id: Int, _ size: Int, _ s: String, limit: Int, maxLines: Int) -> [String] {
            func fits(_ t: String) -> Bool { width1000(id, size, t) <= limit }
            var lines: [String] = []
            var cur = ""
            for w in s.components(separatedBy: " ") {
                var word = w
                if word.isEmpty { continue }
                let cand = cur.isEmpty ? word : cur + " " + word
                if fits(cand) { cur = cand; continue }
                if !cur.isEmpty { lines.append(cur); cur = "" }
                while !fits(word) {
                    let r = Array(word.unicodeScalars)
                    var n = 1
                    while n < r.count, fits(String(String.UnicodeScalarView(r[0..<(n + 1)]))) { n += 1 }
                    lines.append(String(String.UnicodeScalarView(r[0..<n])))
                    word = String(String.UnicodeScalarView(r[n...]))
                }
                cur = word
            }
            if !cur.isEmpty { lines.append(cur) }
            if lines.count > maxLines {
                var last = Array(lines[maxLines - 1].unicodeScalars)
                while !last.isEmpty, !fits(String(String.UnicodeScalarView(last)) + "…") { last.removeLast() }
                lines = Array(lines[0..<(maxLines - 1)]) + [String(String.UnicodeScalarView(last)) + "…"]
            }
            return lines
        }
    }

    static func humanSize(_ b: Int) -> String {
        func tenths(_ b: Int, _ unit: Int) -> String {
            let t = (b * 10 + unit / 2) / unit
            return "\(t / 10).\(t % 10)"
        }
        if b < 1 << 10 { return "\(b) B" }
        if b < 1 << 20 { return tenths(b, 1 << 10) + " KB" }
        if b < 1 << 30 { return tenths(b, 1 << 20) + " MB" }
        return tenths(b, 1 << 30) + " GB"
    }

    static func urlHost(_ u: String) -> String {
        var s = Substring(u)
        if s.hasPrefix("https://") { s = s.dropFirst(8) }
        if s.hasPrefix("http://") { s = s.dropFirst(7) }
        if let i = s.firstIndex(of: "/"), i > s.startIndex {
            let rest = s[s.index(after: i)...]
            if let j = rest.firstIndex(of: "/"), j > rest.startIndex { return String(s[..<j]) }
        }
        return String(s)
    }

    static func literal(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "(", with: "\\(").replacingOccurrences(of: ")", with: "\\)")
    }

    static func asciiURL(_ u: String) -> Bool {
        !u.isEmpty && u.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E && $0 != 0x28 && $0 != 0x29 && $0 != 0x5C }
    }

    static func content(_ p: Data, reg: Font, bld: Font) throws -> (String, [Link]) {
        guard asciiURL(p.verifyURL), p.trustURL.isEmpty || asciiURL(p.trustURL) else { throw DERError("URL is not ASCII") }
        let m = try QR.encode(Array(p.verifyURL.utf8))
        guard let tx = texts[p.lang.isEmpty ? "mn" : p.lang] else { throw DERError("page language \(p.lang)") }
        let w = Writer(reg: reg, bld: bld)
        w.op("\(colBanner) rg")
        w.op(bannerPath)
        w.text(2, 13, 56, 778, colOK, p.brand + tx.title)
        w.text(1, 9, 56, 760, colOK, tx.subtitle)
        var y = 724
        w.hline(y)
        w.text(2, 11, left, y - 17, colText, tx.document)
        y -= 34
        w.text(1, 8, left, y, colMuted, tx.fileName)
        y -= 14
        for (i, line) in w.wrap(2, 10, p.fileName, maxW: width, maxLines: fileNameMax).enumerated() {
            if i > 0 { y -= 14 }
            w.text(2, 10, left, y, colText, line)
        }
        y -= 20
        w.text(1, 8, left, y, colMuted, tx.hashAlg)
        w.text(1, 8, col2, y, colMuted, tx.size)
        w.text(2, 10, left, y - 14, colText, "SHA256")
        w.text(2, 10, col2, y - 14, colText, humanSize(p.fileSize))
        y -= 34
        w.text(1, 8, left, y, colMuted, tx.docHash)
        w.text(3, 9, left, y - 13, colText, p.documentHash)
        y -= 31
        w.text(1, 8, left, y, colMuted, tx.docID)
        w.text(3, 9, left, y - 13, colText, p.docId)
        y -= 35
        w.hline(y)
        w.text(2, 11, left, y - 17, colText, tx.verification)
        y -= 35
        w.text(1, 9, left, y, colLink, p.verifyURL)
        w.link(1, 9, left, y, p.verifyURL)
        y -= 14
        w.op("0 0 0 rg")
        let n = m.count
        for r in 0..<n {
            var c = 0
            while c < n {
                if !m[r][c] { c += 1; continue }
                let s = c
                while c < n, m[r][c] { c += 1 }
                w.op("\(left + qrModule * s) \(y - qrModule * (r + 1)) \(qrModule * (c - s)) \(qrModule) re")
            }
        }
        w.op("f")
        w.text(2, 11, qrTextX, y - 14, colText, tx.scan)
        w.text(1, 9, qrTextX, y - 29, colMuted, tx.scanHint)
        w.text(2, 9, qrTextX, y - 43, colLink, urlHost(p.verifyURL))
        if !p.trustURL.isEmpty {
            w.text(1, 9, qrTextX, y - 60, colMuted, tx.trust)
            w.text(2, 9, qrTextX, y - 74, colLink, p.trustURL)
            w.link(2, 9, qrTextX, y - 74, p.trustURL)
        }
        w.hline(71)
        w.text(1, 8, left, 58, colMuted, "CA: " + p.caName + "  |  TSA: " + p.tsaName + "  |  " + tx.provider + ": " + p.provider)
        return (w.ops, w.links)
    }

    /// Appends the page as an incremental update: page, content, 2 × Type0 font (5 objects each), Courier, links;
    /// then the /Pages root rewritten (/Kids + page — at the end, or at the front when `first`, PAGE_SPEC §8a; /Count + 1).
    /// The Catalog is unchanged.
    static func append(_ base: [UInt8], _ p: Data, first: Bool = false) throws -> [UInt8] {
        let reg = try Font.regular.get(), bld = try Font.bold.get()
        let (content, links) = try content(p, reg: reg, bld: bld)
        let inc = try PdfIncremental(base)
        let r = inc.reader
        guard let rootRef = r.trailer["Root"].refValue, rootRef.gen == 0 else { throw PdfError("Catalog generation is not 0") }
        let root = inc.root
        guard let pp = root["Pages"].refValue, let pages = try r.resolve(root["Pages"]).dict,
              try r.resolve(pages["Type"]).nameValue == "Pages", pp != rootRef, pp.id != 0 else {
            throw PdfError("/Pages root missing")
        }
        guard let count = try r.resolve(pages["Count"]).intValue, count >= 0, let kids = try r.resolve(pages["Kids"]).array else {
            throw PdfError("/Pages /Kids /Count")
        }
        let pageID = inc.reserve(), contentID = inc.reserve()
        let fontIDs = (0..<2).map { _ in (0..<5).map { _ in inc.reserve() } }
        let courierID = inc.reserve()
        let linkIDs = links.map { _ in inc.reserve() }

        var pg = "<< /Type /Page /Parent \(pp.id) \(pp.gen) R /MediaBox \(mediaBox) /CropBox \(mediaBox) /Rotate 0 /Resources << /Font << /F1 \(fontIDs[0][0]) 0 R /F2 \(fontIDs[1][0]) 0 R /F3 \(courierID) 0 R >> >> /Contents \(contentID) 0 R"
        if !linkIDs.isEmpty { pg += " /Annots [" + linkIDs.map { "\($0) 0 R" }.joined(separator: " ") + "]" }
        pg += " >>"
        inc.writeObject(pageID, Array(pg.utf8))
        inc.writeObject(contentID, streamObj("", Array(content.utf8)))
        for (i, f) in [reg, bld].enumerated() { writeFont(inc, fontIDs[i], f) }
        inc.writeObject(courierID, Array("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>".utf8))
        for (i, l) in links.enumerated() {
            inc.writeObject(linkIDs[i], Array("<< /Type /Annot /Subtype /Link /Rect [\(l.x1) \(l.y1) \(l.x2) \(l.y2)] /Border [0 0 0] /A << /S /URI /URI (\(l.url)) >> >>".utf8))
        }
        var pn = "<<"
        for key in pages.sortedKeys where key != "Kids" && key != "Count" {
            pn += " /" + PdfIncremental.escapeName(key) + " " + (try inc.serialize(pages[key]))
        }
        pn += " /Kids ["
        if first {
            pn += "\(pageID) 0 R"
            for k in kids { pn += " " + (try inc.serialize(k)) }
            pn += "] /Count \(count + 1) >>"
        } else {
            for k in kids { pn += try inc.serialize(k) + " " }
            pn += "\(pageID) 0 R] /Count \(count + 1) >>"
        }
        inc.writeObject(pp.id, gen: pp.gen, Array(pn.utf8))
        return try inc.finish(rootID: rootRef.id)
    }

    static func streamObj(_ extra: String, _ data: [UInt8]) -> [UInt8] {
        Array("<< /Length \(data.count)\(extra) >>\nstream\n".utf8) + data + Array("\nendstream".utf8)
    }

    static func writeFont(_ inc: PdfIncremental, _ ids: [Int], _ f: Font) {
        for (i, body) in fontBodies(ids, f).enumerated() { inc.writeObject(ids[i], body) }
    }

    /// The 5 font object bodies (in `ids` order) — shared by the verify page and the visible appearance.
    static func fontBodies(_ ids: [Int], _ f: Font) -> [[UInt8]] {
        let wa = f.widths.map(String.init).joined(separator: " ")
        return [
            Array("<< /Type /Font /Subtype /Type0 /BaseFont /\(f.psName) /Encoding /Identity-H /DescendantFonts [\(ids[1]) 0 R] /ToUnicode \(ids[4]) 0 R >>".utf8),
            Array("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /\(f.psName) /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor \(ids[2]) 0 R /CIDToGIDMap /Identity /W [0 [\(wa)]] >>".utf8),
            Array("<< /Type /FontDescriptor /FontName /\(f.psName) /Flags 32 /FontBBox [\(f.bbox[0]) \(f.bbox[1]) \(f.bbox[2]) \(f.bbox[3])] /ItalicAngle 0 /Ascent \(f.ascent) /Descent \(f.descent) /CapHeight \(f.capHeight) /StemV 80 /FontFile2 \(ids[3]) 0 R >>".utf8),
            streamObj(" /Length1 \(f.length1) /Filter /FlateDecode", f.stream),
            streamObj("", Array(toUnicode(f).utf8)),
        ]
    }

    static func toUnicode(_ f: Font) -> String {
        var uni: [Int: UInt32] = [:]
        for (r, g) in f.gid where uni[g].map({ r < $0 }) ?? true { uni[g] = r }
        var pairs: [(Int, UInt32)] = []
        for g in 0..<f.widths.count { if let r = uni[g] { pairs.append((g, r)) } }
        var b = "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n" +
            "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n" +
            "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n"
        var i = 0
        while i < pairs.count {
            let chunk = pairs[i..<min(i + 100, pairs.count)]
            b += "\(chunk.count) beginbfchar\n"
            for p in chunk { b += String(format: "<%04X> <%04X>\n", UInt32(p.0), p.1) }
            b += "endbfchar\n"
            i += 100
        }
        b += "endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend"
        return b
    }
}
