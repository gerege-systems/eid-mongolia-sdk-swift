import Foundation
import zlib

/// Visible stamp placement — PLACEMENT_SPEC.md (pades-client/1), 1:1 port of the Go reference
/// `pades/internal/core/occupancy.go` (`Occupancy`) and `placement.go` (`PlaceCandidates`, `PlaceVisible`).
/// The requested rect is the preferred spot; the page is scanned (content stream, form XObjects, images, annotations —
/// never rendered) into conservative h100 boxes and the stamp moves to the first free candidate.
///
/// Arithmetic (§2): IEEE-754 binary64, `+ − × ÷` only, each product rounded on its own and the terms summed left to
/// right as written — Swift never contracts `a * b + c` into an FMA (no `-Ounchecked`/fast-math, no `addingProduct`).
enum StampPlacement {
    /// Where the stamp ended up and why (`EidPades.Placement.Status`).
    enum Status: String {
        case requested, moved, overlap, unscanned
    }

    /// The stamp's lower-left corner in visible page space (h100) and how it was chosen.
    struct Result {
        let x, y: Int
        let status: Status
    }

    static let pad = 400        // h100: clearance kept around the stamp
    static let step = 1200      // h100: vertical step between candidates
    static let maxSteps = 100   // at most this many steps up per column

    /// Candidate positions (visible space, h100) in trial order (§6): requested (x, y); mirrored (vw − x − w, y); then up
    /// the requested column y + k·step (k = 1…, while y + k·step + h ≤ vh − y, k ≤ 100); then up the mirrored column.
    /// The mirrored column is left out when it equals the requested one.
    static func candidates(vw: Int, vh: Int, x: Int, y: Int, w: Int, h: Int) -> [(Int, Int)] {
        let xl = vw - x - w
        var out = [(x, y)]
        if xl != x { out.append((xl, y)) }
        let cols = xl != x ? [x, xl] : [x]
        for cx in cols {
            var k = 1
            while k <= maxSteps, y + k * step + h <= vh - y {
                out.append((cx, y + k * step))
                k += 1
            }
        }
        return out
    }

    /// The first candidate whose /Rect, grown by `pad` on every side, overlaps no occupied box (strict overlap: touching
    /// edges are free). nil → none is free (the caller keeps the requested rect).
    static func place(box: [Int], rot: Int, x: Int, y: Int, w: Int, h: Int, occ: [[Int]]) -> (Int, Int)? {
        var vw = box[2] - box[0], vh = box[3] - box[1]
        if rot == 90 || rot == 270 { swap(&vw, &vh) }
        for (cx, cy) in candidates(vw: vw, vh: vh, x: x, y: y, w: w, h: h) {
            guard let r = try? Appearance.rect(box: box, rot: rot, x: cx, y: cy, w: w, h: h) else { continue }
            if free(r, occ) { return (cx, cy) }
        }
        return nil
    }

    /// `r` (user space, h100) grown by `pad` on every side overlaps no occupied box (strict overlap: touching edges are
    /// free) — Go `placeFree`.
    static func free(_ r: [Int], _ occ: [[Int]]) -> Bool {
        let e = [r[0] - pad, r[1] - pad, r[2] + pad, r[3] + pad]
        return !occ.contains(where: { b in b[0] < e[2] && e[0] < b[2] && b[1] < e[3] && e[1] < b[3] })
    }

    /// Scan + choice for a visible stamp at (x, y, w, h) on `page` (reached as object `pageID`) — Go `PlaceOnPage`.
    /// `exact` (§6a): the requested rect is the only candidate (never moved) — `.requested` when free, `.overlap` when not.
    static func choose(_ r: PdfReader, page: PdfDict, pageID: Int, box: [Int], rot: Int,
                       x: Int, y: Int, w: Int, h: Int, exact: Bool = false) -> Result {
        guard let occ = try? Occupancy.scan(r, page: page, pageID: pageID, box: box) else {
            return Result(x: x, y: y, status: .unscanned)
        }
        if exact {
            guard let rect = try? Appearance.rect(box: box, rot: rot, x: x, y: y, w: w, h: h), free(rect, occ) else {
                return Result(x: x, y: y, status: .overlap)
            }
            return Result(x: x, y: y, status: .requested)
        }
        guard let (px, py) = place(box: box, rot: rot, x: x, y: y, w: w, h: h, occ: occ) else {
            return Result(x: x, y: y, status: .overlap)
        }
        return px == x && py == y ? Result(x: x, y: y, status: .requested) : Result(x: px, y: py, status: .moved)
    }

    /// Where the stamp goes on page `page` (1-based, resolved) of the /Pages tree `pages` — the one path shared by
    /// `PadesSignature.prepare` and `EidPades.suggestPlacement` (PLACEMENT_SPEC §6b): page → geometry → the requested
    /// rect must lie inside the page (`Appearance.Failure`) → scan + choice. `rect` is the final /Rect (user space, h100).
    static func locate(_ r: PdfReader, pages: PdfObject, page: Int, x: Int, y: Int, w: Int, h: Int,
                       exact: Bool) throws -> (page: PadesSignature.Page, rot: Int, rect: [Int], result: Result) {
        guard let p = try Appearance.nthPage(r, pages, page) else { throw Appearance.Failure("page \(page) missing") }
        let (box, rot) = try Appearance.geometry(r, p.dict)
        var rect = try Appearance.rect(box: box, rot: rot, x: x, y: y, w: w, h: h)
        // PLACEMENT_SPEC.md: move off existing page content (exact: only report it); the requested rect stays when
        // nothing is free.
        let placed = choose(r, page: p.dict, pageID: p.ref.id, box: box, rot: rot, x: x, y: y, w: w, h: h, exact: exact)
        if placed.status == .moved {
            rect = try Appearance.rect(box: box, rot: rot, x: placed.x, y: placed.y, w: w, h: h)
        }
        return (p, rot, rect, placed)
    }
}

/// Occupancy scanner — PLACEMENT_SPEC.md §3–§5. A pure function of the page objects. Any failure (limit, unsupported
/// filter, broken stream, unparsable object) is `Occupancy.Unscannable` — the stamp then stays where it was requested.
enum Occupancy {
    struct Unscannable: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    // Limits (§5).
    static let maxBytes = 4 << 20       // decoded content bytes, page + every form execution
    static let maxOps = 100_000         // operators executed, page + forms
    static let maxDepth = 8             // form XObject nesting (page content = 0)
    static let maxSave = 64             // q nesting per content stream
    static let maxOperands = 65_536     // operand objects pending at one operator (nested array elements count)
    static let maxNesting = 32          // array / dictionary nesting in an operand
    static let maxAnnots = 10_000       // /Annots entries
    static let maxWEntries = 65_536     // CIDFont /W: elements read (outer array, and each inner array)
    static let maxWAssign = 262_144     // CIDFont /W: CID assignments attempted before reading stops
    static let maxNumLen = 32           // a longer numeric token is not a number
    static let clamp = 1e7              // box coordinates are clamped to ±clamp pt before quantising

    /// Occupied boxes of a page in default user space, h100, outward-rounded, in emission order (content stream, then
    /// /Annots). `box` = the page's normalised CropBox/MediaBox (h100), used only for the background-fill rule.
    static func scan(_ r: PdfReader, page: PdfDict, pageID: Int, box: [Int]) throws -> [[Int]] {
        let s = Scanner(r, box: box)
        let pg = Val(.dict(page), ptr: pageID)
        let content = try s.pageContent(try s.key(pg, "Contents"))
        let res = try s.inherited(pg, "Resources")
        try s.run(content, res: res, g: GState(), depth: 0)
        try s.annots(try s.key(pg, "Annots"))
        return s.boxes
    }

    // MARK: - Values (digitorus/pdf `Value` semantics)

    /// A resolved object and the id of the indirect object it lives in (digitorus `Value.GetPtr()` — the font cache key).
    struct Val {
        let o: PdfObject
        let ptr: Int
        init(_ o: PdfObject, ptr: Int) { self.o = o; self.ptr = ptr }
        static let null = Val(.null, ptr: 0)

        var isNull: Bool { o.isNull }
        var name: String { o.nameValue ?? "" }
        var count: Int { o.array?.count ?? 0 }
        var isDict: Bool { if case .dict = o { return true }; return false }
        var isStream: Bool { if case .stream = o { return true }; return false }
        var isArray: Bool { if case .array = o { return true }; return false }
        /// Integer or real (digitorus Kind Integer | Real).
        var number: Double? {
            switch o {
            case .int(let i): return Double(i)
            case .real(let d): return d
            default: return nil
            }
        }
    }

    // MARK: - Arithmetic (§2)

    typealias Matrix = [Double]   // [a b c d e f]
    static let identity: Matrix = [1, 0, 0, 1, 0, 0]

    /// m × n (row-vector convention), each product rounded on its own, summed left to right.
    static func mul(_ m: Matrix, _ n: Matrix) -> Matrix {
        let a = m[0] * n[0], b = m[1] * n[2]
        let c = m[0] * n[1], d = m[1] * n[3]
        let e = m[2] * n[0], f = m[3] * n[2]
        let g = m[2] * n[1], h = m[3] * n[3]
        let i = m[4] * n[0], j = m[5] * n[2]
        let k = m[4] * n[1], l = m[5] * n[3]
        return [a + b, c + d, e + f, g + h, i + j + n[4], k + l + n[5]]
    }

    /// (x, y) × m = (a·x + c·y + e, b·x + d·y + f).
    static func apply(_ m: Matrix, _ x: Double, _ y: Double) -> (Double, Double) {
        let ax = m[0] * x, cy = m[2] * y
        let bx = m[1] * x, dy = m[3] * y
        return (ax + cy + m[4], bx + dy + m[5])
    }

    static func finite(_ m: Matrix) -> Bool { m.allSatisfy(\.isFinite) }

    /// Go `min`/`max` on float64: NaN wins, −0 < +0.
    static func fmin(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == b { return a.sign == .minus ? a : b }
        return a < b ? a : b
    }
    static func fmax(_ a: Double, _ b: Double) -> Double {
        if a.isNaN || b.isNaN { return .nan }
        if a == b { return a.sign == .minus ? b : a }
        return a > b ? a : b
    }

    /// Go `int(f)` (truncation toward zero), saturating instead of trapping; NaN → 0.
    static func toInt(_ v: Double) -> Int {
        if v.isNaN { return 0 }
        if v >= 9.223372036854775807e18 { return Int.max }
        if v <= -9.223372036854775808e18 { return Int.min }
        return Int(v)
    }

    struct Rect {
        var x0, y0, x1, y1: Double
        init(_ x: Double, _ y: Double) { x0 = x; y0 = y; x1 = x; y1 = y }
        init(_ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double) { self.x0 = x0; self.y0 = y0; self.x1 = x1; self.y1 = y1 }
        mutating func add(_ x: Double, _ y: Double) {
            x0 = fmin(x0, x); y0 = fmin(y0, y); x1 = fmax(x1, x); y1 = fmax(y1, y)
        }
    }

    /// Outward to h100 after clamping to ±clamp pt: floor(min·100), ceil(max·100). NaN → unscannable.
    static func quantise(_ r: Rect) throws -> [Int] {
        var v: [Double] = []
        for x in [r.x0, r.y0, r.x1, r.y1] {
            if x.isNaN { throw Unscannable("NaN") }
            v.append(fmin(fmax(x, -clamp), clamp))
        }
        return [Int((v[0] * 100).rounded(.down)), Int((v[1] * 100).rounded(.down)),
                Int((v[2] * 100).rounded(.up)), Int((v[3] * 100).rounded(.up))]
    }

    // MARK: - Fonts (§3.4)

    final class Font {
        enum Kind { case simple, identity, composite, fallback }
        let kind: Kind
        var first = 0
        var widths: [Double?] = []
        var missing = 1000.0
        var dw = 1000.0
        var w: [Int: Double] = [:]
        init(_ kind: Kind) { self.kind = kind }

        static let fallback = Font(.fallback)

        /// Each code's width (glyph space, 1/1000 em) and whether it is the 1-byte code 32 (word spacing).
        func glyphs(_ b: [UInt8], _ fn: (Double, Bool) -> Void) {
            if kind == .identity {
                var i = 0
                while i + 1 < b.count {
                    let cid = Int(b[i]) << 8 | Int(b[i + 1])
                    fn(w[cid] ?? dw, false)
                    i += 2
                }
                return
            }
            for c in b {
                var w0 = 1000.0
                if kind == .simple {
                    w0 = missing
                    let i = Int(c) &- first
                    if i >= 0, i < widths.count, let x = widths[i] { w0 = x }
                }
                fn(w0, kind != .composite && c == 0x20)
            }
        }
    }

    // MARK: - Content lexer (§3.1)

    enum Operand {
        case num(Double)
        case str([UInt8])
        case name(String)
        case arr([Operand])
        case dict
        case other   // true/false/null, or a keyword inside an array/dictionary

        var number: Double? { if case .num(let v) = self { return v }; return nil }
    }

    enum Token {
        case eof
        case obj(Operand, open: String)   // open = "[" | "<<" for a container to complete, else ""
        case keyword(String)
        case arrEnd
        case dictEnd
    }

    struct Lexer {
        let b: [UInt8]
        var i = 0
        init(_ b: [UInt8]) { self.b = b }

        static func isSpace(_ c: UInt8) -> Bool { c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }
        static func isDelim(_ c: UInt8) -> Bool {
            switch c {
            case 0x28, 0x29, 0x3C, 0x3E, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F, 0x25: return true
            default: return false
            }
        }

        mutating func skipSpace() {
            while i < b.count {
                let c = b[i]
                if Self.isSpace(c) {
                    i += 1
                } else if c == 0x25 {
                    while i < b.count, b[i] != 0x0D, b[i] != 0x0A { i += 1 }
                } else {
                    return
                }
            }
        }

        mutating func regular() -> ArraySlice<UInt8> {
            let s = i
            while i < b.count, !Self.isSpace(b[i]), !Self.isDelim(b[i]) { i += 1 }
            return b[s..<i]
        }

        /// [+-]?(\d+(\.\d*)?|\.\d+), at most maxNumLen bytes.
        static func isNumber(_ t: ArraySlice<UInt8>) -> Bool {
            guard !t.isEmpty, t.count <= maxNumLen else { return false }
            var i = t.startIndex
            if t[i] == 0x2B || t[i] == 0x2D { i += 1 }
            var digits = 0, dot = false
            while i < t.endIndex {
                let c = t[i]
                if c >= 0x30, c <= 0x39 {
                    digits += 1
                } else if c == 0x2E, !dot {
                    dot = true
                } else {
                    return false
                }
                i += 1
            }
            return digits > 0
        }

        static func unhex(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30
            case 0x61...0x66: return c - 0x61 + 10
            case 0x41...0x46: return c - 0x41 + 10
            default: return nil
            }
        }

        /// After '(' : balanced parentheses, escapes; EOF ends the string.
        mutating func literal() -> [UInt8] {
            var out: [UInt8] = []
            var depth = 1
            while i < b.count {
                var c = b[i]
                i += 1
                switch c {
                case 0x28:
                    depth += 1
                case 0x29:
                    depth -= 1
                    if depth == 0 { return out }
                case 0x5C:
                    guard i < b.count else { return out }
                    let e = b[i]
                    i += 1
                    switch e {
                    case 0x6E: c = 0x0A
                    case 0x72: c = 0x0D
                    case 0x74: c = 0x09
                    case 0x62: c = 0x08
                    case 0x66: c = 0x0C
                    case 0x0D:
                        if i < b.count, b[i] == 0x0A { i += 1 }
                        continue
                    case 0x0A:
                        continue
                    case 0x30...0x37:
                        var v = Int(e - 0x30)
                        var k = 0
                        while k < 2, i < b.count, b[i] >= 0x30, b[i] <= 0x37 {
                            v = v * 8 + Int(b[i] - 0x30)
                            i += 1
                            k += 1
                        }
                        c = UInt8(truncatingIfNeeded: v)
                    default:
                        c = e
                    }
                default:
                    break
                }
                out.append(c)
            }
            return out
        }

        /// After '<' : hex digits, other bytes skipped, odd final nibble padded with 0; '>' or EOF ends it.
        mutating func hexString() -> [UInt8] {
            var out: [UInt8] = []
            var hi: UInt8 = 0, half = false
            while i < b.count {
                let c = b[i]
                i += 1
                if c == 0x3E { break }
                guard let v = Self.unhex(c) else { continue }
                if half { out.append(hi << 4 | v) } else { hi = v }
                half.toggle()
            }
            if half { out.append(hi << 4) }
            return out
        }

        /// After '/' : regular bytes, #xx decoded (one byte per scalar, as PdfObject names).
        mutating func name() -> String {
            let t = Array(regular())
            var out = ""
            var k = 0
            while k < t.count {
                if t[k] == 0x23, k + 2 < t.count, let h = Self.unhex(t[k + 1]), let lo = Self.unhex(t[k + 2]) {
                    out.unicodeScalars.append(Unicode.Scalar(h << 4 | lo))
                    k += 3
                    continue
                }
                out.unicodeScalars.append(Unicode.Scalar(t[k]))
                k += 1
            }
            return out
        }

        /// One token; '{' '}' and stray ')' / '>' are skipped.
        mutating func next() -> Token {
            while true {
                skipSpace()
                guard i < b.count else { return .eof }
                switch b[i] {
                case 0x28:
                    i += 1
                    return .obj(.str(literal()), open: "")
                case 0x3C:
                    if i + 1 < b.count, b[i + 1] == 0x3C {
                        i += 2
                        return .obj(.dict, open: "<<")
                    }
                    i += 1
                    return .obj(.str(hexString()), open: "")
                case 0x3E:
                    if i + 1 < b.count, b[i + 1] == 0x3E {
                        i += 2
                        return .dictEnd
                    }
                    i += 1
                    continue
                case 0x5B:
                    i += 1
                    return .obj(.arr([]), open: "[")
                case 0x5D:
                    i += 1
                    return .arrEnd
                case 0x2F:
                    i += 1
                    return .obj(.name(name()), open: "")
                case 0x29, 0x7B, 0x7D:
                    i += 1
                    continue
                default:
                    break
                }
                let t = regular()
                if Self.isNumber(t) {
                    guard let v = Double(String(decoding: t, as: UTF8.self)) else { return .obj(.other, open: "") }
                    return .obj(.num(v), open: "")
                }
                let s = String(decoding: t, as: UTF8.self)
                switch s {
                case "true", "false", "null": return .obj(.other, open: "")
                default: return .keyword(s)
                }
            }
        }

        /// Completes an array or dictionary opened by `next` (open = "[" or "<<"). Inside, every token is an element;
        /// EOF ends the content (eof = true). Nesting > maxNesting or too many elements → unscannable.
        mutating func object(_ o: Operand, open: String, depth: Int, count: inout Int) throws -> (Operand, Bool) {
            if open.isEmpty { return (o, false) }
            if depth >= maxNesting { throw Unscannable("nesting") }
            var elems: [Operand] = []
            func done() -> Operand { open == "[" ? .arr(elems) : o }
            while true {
                var e: Operand
                switch next() {
                case .eof:
                    return (done(), true)
                case .arrEnd:
                    if open == "[" { return (done(), false) }
                    continue
                case .dictEnd:
                    if open == "<<" { return (done(), false) }
                    continue
                case .keyword:
                    e = .other
                case .obj(let x, let kw):
                    let (y, eof) = try object(x, open: kw, depth: depth + 1, count: &count)
                    if eof { return (done(), true) }
                    e = y
                }
                count += 1
                if count > maxOperands { throw Unscannable("operands") }
                if open == "[" { elems.append(e) }
            }
        }
    }

    // MARK: - Interpreter (§3.2–§3.6)

    struct GState {
        var ctm = identity
        var lw = 1.0
        var fillWhite = false, strokeWhite = false
        var tc = 0.0, tw = 0.0, th = 1.0, tl = 0.0, tfs = 0.0, trise = 0.0
        var font = Font.fallback
    }

    final class Subpath {
        var sx, sy, cx, cy: Double
        var bbox: Rect
        var segs: [Rect] = []
        init(_ x: Double, _ y: Double) { sx = x; sy = y; cx = x; cy = y; bbox = Rect(x, y) }

        func close() {
            var seg = Rect(cx, cy)
            seg.add(sx, sy)
            segs.append(seg)
            cx = sx; cy = sy
        }
    }

    final class Scanner {
        let r: PdfReader
        let page: [Int]
        var bytes = 0
        var ops = 0
        var boxes: [[Int]] = []
        var fonts: [Int: Font] = [:]

        init(_ r: PdfReader, box: [Int]) { self.r = r; page = box }

        // digitorus resolve: a reference becomes the object it names (ptr = its id); a missing object is null; a reference
        // to a reference is a reader failure.
        func res(_ x: PdfObject, parent: Int) throws -> Val {
            guard case .ref(let ref) = x else { return Val(x, ptr: parent) }
            let y = try r.object(ref)
            if case .ref = y { throw Unscannable("reference to a reference") }
            if y.isNull { return .null }
            return Val(y, ptr: ref.id)
        }

        func key(_ v: Val, _ k: String) throws -> Val {
            guard let d = v.o.dict else { return .null }
            return try res(d[k], parent: v.ptr)
        }

        func index(_ v: Val, _ i: Int) throws -> Val {
            guard let a = v.o.array, i >= 0, i < a.count else { return .null }
            return try res(a[i], parent: v.ptr)
        }

        /// A page attribute, following /Parent (depth ≤ 32).
        func inherited(_ page: Val, _ k: String) throws -> Val {
            var v = page
            for _ in 0..<32 {
                let x = try key(v, k)
                if !x.isNull { return x }
                v = try key(v, "Parent")
                if !v.isDict { break }
            }
            return .null
        }

        func emit(_ rc: Rect) throws { boxes.append(try quantise(rc)) }

        /// Decoded bytes of a content/form stream: no filter, or exactly FlateDecode without parameters (§3.1).
        func stream(_ v: Val) throws -> [UInt8] {
            guard case .stream(_, let range) = v.o else { throw Unscannable("not a stream") }
            let f = try key(v, "Filter"), p = try key(v, "DecodeParms")
            let flate: Bool
            if f.isNull, p.isNull {
                flate = false
            } else if f.name == "FlateDecode", case .name = f.o, p.isNull {
                flate = true
            } else if f.isArray, f.count == 1, case .name("FlateDecode") = try index(f, 0).o,
                      try p.isNull || (p.isArray && p.count == 1 && index(p, 0).isNull) {
                flate = true
            } else {
                throw Unscannable("filter")
            }
            guard range.lowerBound >= 0, range.upperBound <= r.bytes.count else { throw Unscannable("stream range") }
            let raw = Array(r.bytes[range])
            let left = maxBytes - bytes
            let out = flate ? try Occupancy.inflate(raw, limit: left) : raw
            if out.count > left { throw Unscannable("content bytes") }
            bytes += out.count
            return out
        }

        /// /Contents: absent → empty; a stream; or an array of streams joined with LF.
        func pageContent(_ c: Val) throws -> [UInt8] {
            switch c.o {
            case .null: return []
            case .stream: return try stream(c)
            case .array(let a):
                var out: [UInt8] = []
                for i in 0..<a.count {
                    let b = try stream(try index(c, i))
                    if i > 0 { out.append(0x0A) }
                    out += b
                }
                return out
            default: throw Unscannable("/Contents")
            }
        }

        func font(_ v: Val) throws -> Font {
            guard v.isDict else { return Font.fallback }
            if v.ptr != 0, let f = fonts[v.ptr] { return f }
            let f = try loadFont(v)
            if v.ptr != 0 { fonts[v.ptr] = f }
            return f
        }

        func loadFont(_ v: Val) throws -> Font {
            switch try key(v, "Subtype").name {
            case "Type3":
                return Font.fallback
            case "Type0":
                let enc = try key(v, "Encoding")
                guard case .name(let en) = enc.o, en == "Identity-H" || en == "Identity-V" else { return Font(.composite) }
                let f = Font(.identity)
                let d = try index(try key(v, "DescendantFonts"), 0)
                if let dw = try key(d, "DW").number { f.dw = dw }
                let w = try key(d, "W")
                let n = min(w.count, maxWEntries)
                var budget = maxWAssign
                func set(_ cid: Int, _ val: Double) -> Bool {
                    budget -= 1
                    if budget < 0 { return false }
                    if f.w[cid] == nil, cid >= 0, cid <= 0xFFFF { f.w[cid] = val }
                    return true
                }
                var i = 0
                read: while i < n {
                    guard let c0 = try index(w, i).number, i + 1 < n else { break }
                    let arr = try index(w, i + 1)
                    if arr.isArray {
                        for j in 0..<min(arr.count, maxWEntries) {
                            if let x = try index(arr, j).number, !set(toInt(c0) &+ j, x) { break read }
                        }
                        i += 2
                        continue
                    }
                    let c1 = try index(w, i + 1).number, x = try index(w, i + 2).number
                    guard let c1, let x, i + 2 < n else { break }
                    var c = max(toInt(c0), 0)
                    let hi = toInt(c1)
                    while c <= hi, c <= 0xFFFF {
                        if !set(c, x) { break read }
                        c += 1
                    }
                    i += 3
                }
                return f
            default:
                break
            }
            let f = Font(.simple)
            if let fc = try key(v, "FirstChar").number { f.first = toInt(fc) }
            let ws = try key(v, "Widths")
            for i in 0..<min(ws.count, 256) { f.widths.append(try index(ws, i).number) }
            if let mw = try key(try key(v, "FontDescriptor"), "MissingWidth").number, mw > 0 { f.missing = mw }
            return f
        }

        static func nums(_ ops: [Operand], _ n: Int) -> [Double]? {
            guard ops.count == n else { return nil }
            var out: [Double] = []
            for o in ops {
                guard let v = o.number else { return nil }
                out.append(v)
            }
            return out
        }

        /// Executes one content stream (page content or a form) from graphics state `g0`, with its own operand stack,
        /// q stack, path and text matrices.
        func run(_ content: [UInt8], res: Val, g g0: GState, depth: Int) throws {
            var l = Lexer(content)
            var g = g0
            var stack: [GState] = []
            var path: [Subpath] = []
            var tm = identity, tlm = identity
            var opnds: [Operand] = []
            var count = 0
            func textMatrix(_ m: Matrix) throws -> Matrix {
                guard finite(m) else { throw Unscannable("text matrix") }
                return m
            }
            while true {
                let kw: String
                switch l.next() {
                case .eof:
                    return
                case .arrEnd, .dictEnd:
                    continue
                case .obj(let o, let open):
                    let (x, eof) = try l.object(o, open: open, depth: 0, count: &count)
                    if eof { return }
                    count += 1
                    if count > maxOperands { throw Unscannable("operands") }
                    opnds.append(x)
                    continue
                case .keyword(let k):
                    kw = k
                }
                ops += 1
                if ops > maxOps { throw Unscannable("operators") }
                let args = opnds
                opnds.removeAll(keepingCapacity: true)
                count = 0
                switch kw {
                case "q", "Q", "BT":
                    guard args.isEmpty else { break }
                    switch kw {
                    case "BT":
                        tm = identity; tlm = identity
                    case "Q":
                        if let last = stack.popLast() { g = last }
                    default:
                        if stack.count >= maxSave { throw Unscannable("q nesting") }
                        stack.append(g)
                    }
                case "cm":
                    if let v = Self.nums(args, 6) {
                        g.ctm = mul(v, g.ctm)
                        if !finite(g.ctm) { throw Unscannable("CTM") }
                    }
                case "w":
                    if let v = Self.nums(args, 1) { g.lw = v[0] }
                case "g":
                    if let v = Self.nums(args, 1) { g.fillWhite = v[0] >= 1 }
                case "G":
                    if let v = Self.nums(args, 1) { g.strokeWhite = v[0] >= 1 }
                case "rg":
                    if let v = Self.nums(args, 3) { g.fillWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1 }
                case "RG":
                    if let v = Self.nums(args, 3) { g.strokeWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1 }
                case "k":
                    if let v = Self.nums(args, 4) { g.fillWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0 }
                case "K":
                    if let v = Self.nums(args, 4) { g.strokeWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0 }
                case "cs", "sc", "scn":
                    g.fillWhite = false
                case "CS", "SC", "SCN":
                    g.strokeWhite = false

                // ── Path construction (points transformed by the CTM when given) ──
                case "m":
                    if let v = Self.nums(args, 2) {
                        let (x, y) = apply(g.ctm, v[0], v[1])
                        path.append(Subpath(x, y))
                    }
                case "l", "c", "v", "y":
                    let n = kw == "l" ? 2 : kw == "c" ? 6 : 4
                    guard let v = Self.nums(args, n), let sp = path.last else { break }
                    var seg = Rect(sp.cx, sp.cy)
                    var i = 0
                    while i < n {
                        let (x, y) = apply(g.ctm, v[i], v[i + 1])
                        seg.add(x, y)
                        sp.bbox.add(x, y)
                        sp.cx = x; sp.cy = y
                        i += 2
                    }
                    sp.segs.append(seg)
                case "h":
                    if args.isEmpty, let sp = path.last { sp.close() }
                case "re":
                    if let v = Self.nums(args, 4) {
                        let (x0, y0) = apply(g.ctm, v[0], v[1])
                        let (x1, y1) = apply(g.ctm, v[0] + v[2], v[1])
                        let (x2, y2) = apply(g.ctm, v[0] + v[2], v[1] + v[3])
                        let (x3, y3) = apply(g.ctm, v[0], v[1] + v[3])
                        let sp = Subpath(x0, y0)
                        for (px, py) in [(x1, y1), (x2, y2), (x3, y3)] {
                            var seg = Rect(sp.cx, sp.cy)
                            seg.add(px, py)
                            sp.segs.append(seg)
                            sp.bbox.add(px, py)
                            sp.cx = px; sp.cy = py
                        }
                        sp.close()
                        path.append(sp)
                    }
                case "S", "s", "f", "F", "f*", "B", "B*", "b", "b*", "n":
                    guard args.isEmpty else { break }
                    if kw == "s" || kw == "b" || kw == "b*", let sp = path.last { sp.close() }
                    let fill = kw != "S" && kw != "s" && kw != "n"
                    let stroke = kw == "S" || kw == "s" || kw == "B" || kw == "B*" || kw == "b" || kw == "b*"
                    if fill, !g.fillWhite { try self.fill(path) }
                    if stroke, !g.strokeWhite { try self.stroke(path, g) }
                    path = []

                // ── Text ──
                case "Tc":
                    if let v = Self.nums(args, 1) { g.tc = v[0] }
                case "Tw":
                    if let v = Self.nums(args, 1) { g.tw = v[0] }
                case "Tz":
                    if let v = Self.nums(args, 1) { g.th = v[0] / 100 }
                case "TL":
                    if let v = Self.nums(args, 1) { g.tl = v[0] }
                case "Ts":
                    if let v = Self.nums(args, 1) { g.trise = v[0] }
                case "Tf":
                    if args.count == 2, case .name(let fname) = args[0], case .num(let size) = args[1] {
                        g.font = try font(try key(try key(res, "Font"), fname))
                        g.tfs = size
                    }
                case "Td", "TD":
                    if let v = Self.nums(args, 2) {
                        if kw == "TD" { g.tl = -v[1] }
                        tlm = try textMatrix(mul([1, 0, 0, 1, v[0], v[1]], tlm))
                        tm = tlm
                    }
                case "T*":
                    if args.isEmpty {
                        tlm = try textMatrix(mul([1, 0, 0, 1, 0, -g.tl], tlm))
                        tm = tlm
                    }
                case "Tm":
                    if let v = Self.nums(args, 6) { tm = v; tlm = v }
                case "Tj", "'", "\"", "TJ":
                    var items: [Operand]
                    if (kw == "Tj" || kw == "'"), args.count == 1, case .str = args[0] {
                        items = args
                    } else if kw == "\"", args.count == 3, case .num(let aw) = args[0], case .num(let ac) = args[1],
                              case .str = args[2] {
                        g.tw = aw; g.tc = ac
                        items = [args[2]]
                    } else if kw == "TJ", args.count == 1, case .arr(let a) = args[0] {
                        items = a
                    } else {
                        continue
                    }
                    if kw == "'" || kw == "\"" {
                        tlm = try textMatrix(mul([1, 0, 0, 1, 0, -g.tl], tlm))
                        tm = tlm
                    }
                    tm = try show(items, g, tm)
                case "Do":
                    guard args.count == 1, case .name(let xname) = args[0] else { break }
                    let x = try key(try key(res, "XObject"), xname)
                    switch try key(x, "Subtype").name {
                    case "Image":
                        try unitSquare(g.ctm)
                    case "Form":
                        guard x.isStream else { break }
                        if depth + 1 > maxDepth { throw Unscannable("form depth") }
                        var fm = identity
                        let m = try key(x, "Matrix")
                        if m.isArray, m.count == 6 {
                            var v: Matrix = []
                            for i in 0..<6 {
                                guard let n = try index(m, i).number else { break }
                                v.append(n)
                            }
                            if v.count == 6 { fm = v }
                        }
                        let ctm = mul(fm, g.ctm)
                        if !finite(ctm) { throw Unscannable("form matrix") }
                        var fres = try key(x, "Resources")
                        if !fres.isDict { fres = res }
                        let b = try stream(x)
                        var fg = g
                        fg.ctm = ctm
                        try run(b, res: fres, g: fg, depth: depth + 1)
                    default:
                        break
                    }
                case "BI":
                    try inlineImage(&l, g.ctm)
                default:
                    break
                }
            }
        }

        /// One box per subpath; a subpath box covering ≥ half of the page box is a background and is skipped.
        func fill(_ path: [Subpath]) throws {
            for sp in path {
                let q = try quantise(sp.bbox)
                let w = min(q[2], page[2]) - max(q[0], page[0]), h = min(q[3], page[3]) - max(q[1], page[1])
                if w > 0, h > 0, 2 * w * h >= (page[2] - page[0]) * (page[3] - page[1]) { continue }
                boxes.append(q)
            }
        }

        /// One box per segment, widened by half the line width mapped through the CTM (|a|+|c|, |b|+|d|).
        func stroke(_ path: [Subpath], _ g: GState) throws {
            let hw = abs(g.lw) / 2
            let ea = hw * abs(g.ctm[0]), ec = hw * abs(g.ctm[2])
            let eb = hw * abs(g.ctm[1]), ed = hw * abs(g.ctm[3])
            let ex = ea + ec, ey = eb + ed
            for sp in path {
                for rc in sp.segs { try emit(Rect(rc.x0 - ex, rc.y0 - ey, rc.x1 + ex, rc.y1 + ey)) }
            }
        }

        func unitSquare(_ ctm: Matrix) throws {
            let (x, y) = apply(ctm, 0, 0)
            var rc = Rect(x, y)
            for (px, py) in [(1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
                let (tx, ty) = apply(ctm, px, py)
                rc.add(tx, ty)
            }
            try emit(rc)
        }

        /// One box per string/array operand: [min, max] of glyph extents in text space × [rise − 0.3·Tfs, rise + Tfs],
        /// through Tm then the CTM. Returns the advanced Tm.
        func show(_ items: [Operand], _ g: GState, _ tm: Matrix) throws -> Matrix {
            var x = 0.0
            var ext: (Double, Double)?
            for it in items {
                switch it {
                case .num(let n):
                    let a = n / 1000 * g.tfs
                    x -= a * g.th
                case .str(let s):
                    g.font.glyphs(s) { w0, space in
                        let gwa = w0 / 1000 * g.tfs
                        let gw = gwa * g.th
                        let xe = x + gw
                        let lo = fmin(x, xe), hi = fmax(x, xe)
                        if let e = ext { ext = (fmin(e.0, lo), fmax(e.1, hi)) } else { ext = (lo, hi) }
                        var adv = gwa + g.tc
                        if space { adv += g.tw }
                        let dx = adv * g.th
                        x += dx
                    }
                default:
                    break
                }
            }
            if let (e0, e1) = ext {
                let ra = g.tfs * -0.3
                let ya = g.trise + ra, yb = g.trise + g.tfs
                var rc: Rect?
                for (px, py) in [(e0, ya), (e1, ya), (e0, yb), (e1, yb)] {
                    let (tx, ty) = apply(tm, px, py)
                    let (dx, dy) = apply(g.ctm, tx, ty)
                    if rc == nil { rc = Rect(dx, dy) } else { rc!.add(dx, dy) }
                }
                try emit(rc!)
            }
            let out = mul([1, 0, 0, 1, x, 0], tm)
            guard finite(out) else { throw Unscannable("text matrix") }
            return out
        }

        /// BI <key value>… ID <data> EI: data ends at the first "EI" preceded by a whitespace byte and followed by a
        /// whitespace byte or the end of the content. No EI → the content ends (no box).
        func inlineImage(_ l: inout Lexer, _ ctm: Matrix) throws {
            var count = 0
            scan: while true {
                switch l.next() {
                case .eof:
                    return
                case .obj(let o, let open):
                    let (_, eof) = try l.object(o, open: open, depth: 0, count: &count)
                    if eof { return }
                case .keyword(let k):
                    if k == "ID" { break scan }
                default:
                    continue
                }
            }
            if l.i < l.b.count, Lexer.isSpace(l.b[l.i]) { l.i += 1 }
            var p = l.i
            while p + 1 < l.b.count {
                if l.b[p] == 0x45, l.b[p + 1] == 0x49, p > 0, Lexer.isSpace(l.b[p - 1]),
                   p + 2 == l.b.count || Lexer.isSpace(l.b[p + 2]) {
                    l.i = p + 2
                    try unitSquare(ctm)
                    return
                }
                p += 1
            }
            l.i = l.b.count
        }

        /// /Rect of every annotation except /Popup, hidden (/F bit 2) or NoView (/F bit 6) and zero-area rects.
        func annots(_ a: Val) throws {
            guard a.isArray else { return }
            if a.count > maxAnnots { throw Unscannable("annotations") }
            for i in 0..<a.count {
                let an = try index(a, i)
                guard an.isDict, try key(an, "Subtype").name != "Popup" else { continue }
                if case .int(let f) = try key(an, "F").o, f & (2 | 32) != 0 { continue }
                let rc = try key(an, "Rect")
                guard rc.isArray, rc.count == 4 else { continue }
                var v: [Double] = []
                for j in 0..<4 {
                    guard let n = try index(rc, j).number else { break }
                    v.append(n)
                }
                guard v.count == 4, v[0] != v[2], v[1] != v[3] else { continue }
                try emit(Rect(fmin(v[0], v[2]), fmin(v[1], v[3]), fmax(v[0], v[2]), fmax(v[1], v[3])))
            }
        }
    }

    /// zlib (RFC 1950) inflate, strict: valid header, raw deflate to its final block, Adler-32 must match; bytes after
    /// the checksum are ignored. Truncation or any error → unscannable; output over `limit` → unscannable.
    /// (The system libz checks the header — CM 8, CINFO ≤ 7, FCHECK — and the Adler-32 trailer; FDICT as Go, below.)
    /// `exactEnd`: bytes after the Adler-32 are an error too (Go `zlib.NewReader` on a `bytes.Reader` + `Len() == 0`).
    static func inflate(_ input: [UInt8], limit: Int, exactEnd: Bool = false) throws -> [UInt8] {
        var s = z_stream()
        guard inflateInit_(&s, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK else { throw Unscannable("inflateInit") }
        defer { inflateEnd(&s) }
        var out: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 << 10)
        var src = input
        let rc: Int32 = src.withUnsafeMutableBufferPointer { inBuf -> Int32 in
            s.next_in = inBuf.baseAddress
            s.avail_in = uInt(inBuf.count)
            while true {
                let st = chunk.withUnsafeMutableBufferPointer { outBuf -> Int32 in
                    s.next_out = outBuf.baseAddress
                    s.avail_out = uInt(outBuf.count)
                    return zlib.inflate(&s, Z_NO_FLUSH)
                }
                out.append(contentsOf: chunk[0..<(chunk.count - Int(s.avail_out))])
                if out.count > limit { return Z_MEM_ERROR }
                if st == Z_NEED_DICT {
                    // FDICT: Go compress/zlib accepts a preset dictionary only when DICTID = Adler-32 of its nil
                    // dictionary (1) and inflates on; any other DICTID → ErrDictionary. Same here: the empty
                    // dictionary's Adler-32 is 1, so inflateSetDictionary fails (Z_DATA_ERROR) for every other id.
                    var none: UInt8 = 0
                    guard inflateSetDictionary(&s, &none, 0) == Z_OK else { return Z_DATA_ERROR }
                    continue
                }
                if st != Z_OK { return st }       // Z_STREAM_END = done; Z_BUF_ERROR = truncated; others = corrupt
            }
        }
        guard rc == Z_STREAM_END else { throw Unscannable("FlateDecode (\(rc))") }
        if exactEnd, s.avail_in != 0 { throw Unscannable("bytes after the zlib stream") }
        return out
    }
}
