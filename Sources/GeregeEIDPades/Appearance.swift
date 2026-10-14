import Foundation

/// Visible signature appearance — APPEARANCE_SPEC.md (pades-client/1), 1:1 port of the Go reference
/// `pades/internal/core/appearance.go`. The widget sits on the chosen page with a /Rect, its /AP /N is an uncompressed
/// form XObject (the verify page's font assets, own QR). Every length/coordinate is an integer in 1/100 pt (h100),
/// written with `num100`.
enum Appearance {
    /// Placement/size/page invalid or the text does not fit — REQUEST_INVALID.
    struct Failure: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    /// PadesSignature.prepare input: placement (display space of the page, h100) and text.
    struct Visible {
        /// 1-based, resolved (not 0).
        var page: Int
        var x, y, w, h: Int
        var name: String
        var role: String
        var lang: String
        /// «YYYY-MM-DD HH:MM (+08)»
        var date: String
        /// https://ca.eidmongolia.mn/verify/<docID>/<revIndex>
        var url: String
    }

    struct Params {
        /// Display (after /Rotate) width/height, h100.
        var w, h: Int
        var rotate: Int
        var name, role, lang, date, url: String
    }

    static let pad = 400, gap = 400, minModule = 100
    static let maxSize = 11, minSize = 7, bodyDelta = 2, leading = 125, descent = 25, maxLines = 2
    /// Maximum width/height (14400 pt), h100.
    static let maxSide = 1_440_000
    static let maxDepth = 32

    static let labels: [String: String] = [
        "mn": "eID Mongolia-аар зурсан",
        "en": "Signed with eID Mongolia",
    ]

    /// pt → h100: floor(v × 100 + 0.5).
    static func round100(_ v: Double) -> Int { Int((v * 100 + 0.5).rounded(.down)) }

    /// h100 → PDF number: "N", "N.d", "N.dd" (no trailing zero), "-" for negatives.
    static func num100(_ v: Int) -> String {
        var v = v
        var sign = ""
        if v < 0 { sign = "-"; v = -v }
        var s = sign + String(v / 100)
        let f = v % 100
        if f != 0 { s += f % 10 == 0 ? "." + String(f / 10) : String(format: ".%02d", f) }
        return s
    }

    static func rotation(_ rot: Int, _ w: Int, _ h: Int) throws -> (cm: String, bw: Int, bh: Int) {
        switch rot {
        case 0: return ("", w, h)
        case 90: return ("0 1 -1 0 \(num100(h)) 0 cm", h, w)
        case 180: return ("-1 0 0 -1 \(num100(w)) \(num100(h)) cm", w, h)
        case 270: return ("0 -1 1 0 0 \(num100(w)) cm", h, w)
        default: throw Failure("/Rotate \(rot)")
        }
    }

    private struct Line { let font, size: Int; let color, text: String }

    /// Form XObject content stream (APPEARANCE_SPEC.md §3).
    static func content(_ p: Params) throws -> String {
        guard let label = labels[p.lang] else { throw Failure("lang \(p.lang)") }
        guard VerifyPage.asciiURL(p.url) else { throw Failure("URL is not ASCII") }
        guard p.w > 0, p.h > 0, p.w <= maxSide, p.h <= maxSide else { throw Failure("size") }
        let m: [[Bool]]
        do { m = try QR.encode(Array(p.url.utf8)) } catch { throw Failure("\(error)") }
        let n = m.count
        let mod = (p.h - 2 * pad) / n
        guard mod >= minModule else { throw Failure("too small (height ≥ \(num100(2 * pad + n * minModule)) pt)") }
        let tx = pad + mod * n + gap
        let tw = p.w - tx - pad
        let w = VerifyPage.Writer(reg: try VerifyPage.Font.regular.get(), bld: try VerifyPage.Font.bold.get())
        var lines: [Line]?
        var f = maxSize
        while f >= minSize, lines == nil, tw > 0 {
            lines = layout(w, p, label, f, tw)
            f -= 1
        }
        guard let lines else { throw Failure("too small (text does not fit)") }
        let total = lines.reduce(0) { $0 + $1.size * leading }
        let cm = try rotation(p.rotate, p.w, p.h).cm
        w.op("/EIDVerify <</URL (\(p.url))>> BDC")
        if !cm.isEmpty {
            w.op("q")
            w.op(cm)
        }
        w.op("\(VerifyPage.colOK) RG")
        w.op("1 w")
        w.op("0.5 0.5 \(num100(p.w - 100)) \(num100(p.h - 100)) re S")
        w.op("q \(num100(mod)) 0 0 \(num100(mod)) \(num100(pad)) \(num100((p.h - mod * n) / 2)) cm")
        w.op("0 0 0 rg")
        for r in 0..<n {
            var c = 0
            while c < n {
                if !m[r][c] { c += 1; continue }
                let s = c
                while c < n, m[r][c] { c += 1 }
                w.op("\(s) \(n - 1 - r) \(c - s) 1 re")
            }
        }
        w.op("f")
        w.op("Q")
        var cursor = p.h - pad - (p.h - 2 * pad - total) / 2
        for l in lines {
            cursor -= l.size * leading
            w.op("\(l.color) rg")
            w.op("BT /F\(l.font) \(l.size) Tf \(num100(tx)) \(num100(cursor + l.size * descent)) Td \(w.glyphHex(l.font, l.text)) Tj ET")
        }
        if !cm.isEmpty { w.op("Q") }
        w.op("EMC")
        return w.ops
    }

    /// Lines for name font size `f`: name (F2, f, ≤ 2 lines), role (F1, f−2, ≤ 2 lines), label, date (F1, f−2).
    /// nil when a line is wider than `tw` or the total height exceeds H − 2·pad.
    private static func layout(_ w: VerifyPage.Writer, _ p: Params, _ label: String, _ f: Int, _ tw: Int) -> [Line]? {
        let b = f - bodyDelta
        let limit = tw * 10
        var lines: [Line] = []
        for t in w.wrapLimit(2, f, p.name, limit: limit, maxLines: maxLines) {
            lines.append(Line(font: 2, size: f, color: VerifyPage.colText, text: t))
        }
        if !p.role.isEmpty {
            for t in w.wrapLimit(1, b, p.role, limit: limit, maxLines: maxLines) {
                lines.append(Line(font: 1, size: b, color: VerifyPage.colText, text: t))
            }
        }
        lines.append(Line(font: 1, size: b, color: VerifyPage.colOK, text: label))
        lines.append(Line(font: 1, size: b, color: VerifyPage.colMuted, text: p.date))
        var total = 0
        for l in lines {
            if l.text.isEmpty || w.width1000(l.font, l.size, l.text) > limit { return nil }
            total += l.size * leading
        }
        return total > p.h - 2 * pad ? nil : lines
    }

    /// /AP /N form XObject + its 2 fonts (11 objects): ids = [form, F1 ×5, F2 ×5]. Returns the bodies in `ids` order.
    static func objects(_ p: Params, ids: [Int]) throws -> [[UInt8]] {
        let reg = try VerifyPage.Font.regular.get(), bld = try VerifyPage.Font.bold.get()
        let (_, bw, bh) = try rotation(p.rotate, p.w, p.h)
        let content = try content(p)
        let form = VerifyPage.streamObj(
            " /Type /XObject /Subtype /Form /BBox [0 0 \(num100(bw)) \(num100(bh))] /Resources << /Font << /F1 \(ids[1]) 0 R /F2 \(ids[6]) 0 R >> >>",
            Array(content.utf8))
        return [form] + VerifyPage.fontBodies(Array(ids[1..<6]), reg) + VerifyPage.fontBodies(Array(ids[6..<11]), bld)
    }

    /// Visible field/widget body (APPEARANCE_SPEC.md §2). rect — user space [x1 y1 x2 y2] (h100).
    static func widget(fieldName: String, rect: [Int], page: PdfRef, sigID: Int, formID: Int) -> [UInt8] {
        Array(("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [\(rect.map(num100).joined(separator: " "))]\n  /P \(page.id) \(page.gen) R\n" +
               "  /F 4\n  /FT /Sig\n  /T (\(fieldName))\n  /V \(sigID) 0 R\n  /AP << /N \(formID) 0 R >>\n>>").utf8)
    }

    /// Display (x, y, w, h) → user-space /Rect (APPEARANCE_SPEC.md §1).
    static func rect(box: [Int], rot: Int, x: Int, y: Int, w: Int, h: Int) throws -> [Int] {
        let bw = box[2] - box[0], bh = box[3] - box[1]
        let (vw, vh) = rot == 90 || rot == 270 ? (bh, bw) : (bw, bh)
        guard x >= 0, y >= 0, w > 0, h > 0, x + w <= vw, y + h <= vh else { throw Failure("rectangle outside the page (CropBox)") }
        func pt(_ vx: Int, _ vy: Int) -> (Int, Int) {
            switch rot {
            case 90: return (box[2] - vy, box[1] + vx)
            case 180: return (box[2] - vx, box[3] - vy)
            case 270: return (box[0] + vy, box[3] - vx)
            default: return (box[0] + vx, box[1] + vy)
            }
        }
        let (x1, y1) = pt(x, y), (x2, y2) = pt(x + w, y + h)
        return [min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2)]
    }

    /// Page's (inherited) CropBox (else MediaBox) normalised in h100, and /Rotate (0–270).
    static func geometry(_ r: PdfReader, _ page: PdfDict) throws -> (box: [Int], rot: Int) {
        func inh(_ key: String) throws -> PdfObject? {
            var d = page
            for _ in 0..<maxDepth {
                let x = try r.resolve(d[key])
                if !x.isNull { return x }
                guard let parent = try r.resolve(d["Parent"]).dict else { break }
                d = parent
            }
            return nil
        }
        guard let b = try inh("CropBox") ?? inh("MediaBox"), let arr = b.array, arr.count == 4 else {
            throw Failure("page MediaBox missing")
        }
        var f: [Int] = []
        for e in arr {
            let v: Double
            switch try r.resolve(e) {
            case .int(let i): v = Double(i)
            case .real(let d): v = d
            default: throw Failure("page box invalid")
            }
            guard v.isFinite, abs(v) <= 1e7 else { throw Failure("page box invalid") }
            f.append(round100(v))
        }
        let box = [min(f[0], f[2]), min(f[1], f[3]), max(f[0], f[2]), max(f[1], f[3])]
        var rot = 0
        if let rv = try inh("Rotate") {
            guard case .int(let i) = rv, i % 90 == 0 else { throw Failure("page /Rotate is not a multiple of 90") }
            rot = Int((i % 360 + 360) % 360)
        }
        return (box, rot)
    }

    /// n-th (1-based) /Page of the /Pages tree in tree order (depth ≤ 32).
    static func nthPage(_ r: PdfReader, _ root: PdfObject, _ n: Int) throws -> PadesSignature.Page? {
        guard n >= 1 else { return nil }
        var left = n
        func walk(_ node: PdfObject, _ depth: Int) throws -> PadesSignature.Page? {
            guard depth <= maxDepth, let d = try r.resolve(node).dict else { return nil }
            switch try r.resolve(d["Type"]).nameValue {
            case "Page":
                left -= 1
                guard left == 0, let ref = node.refValue else { return nil }
                return PadesSignature.Page(ref: ref, dict: d)
            case "Pages":
                for kid in try r.resolve(d["Kids"]).array ?? [] {
                    if let p = try walk(kid, depth + 1) { return p }
                    if left <= 0 { break }
                }
            default: break
            }
            return nil
        }
        return try walk(root, 0)
    }

    /// Number of /Page objects in the /Pages tree (counted, /Count is not trusted).
    static func pageCount(_ doc: [UInt8]) throws -> Int {
        let inc = try PdfIncremental(doc)
        let r = inc.reader
        var n = 0
        func walk(_ node: PdfObject, _ depth: Int) throws {
            guard depth <= maxDepth, n <= 1 << 16, let d = try r.resolve(node).dict else { return }
            switch try r.resolve(d["Type"]).nameValue {
            case "Page": n += 1
            case "Pages":
                for kid in try r.resolve(d["Kids"]).array ?? [] { try walk(kid, depth + 1) }
            default: break
            }
        }
        try walk(inc.root["Pages"], 0)
        return n
    }
}
