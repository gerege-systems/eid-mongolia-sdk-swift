import Foundation

// Minimal PDF object model + lexer for the client-side PAdES writer (ISO 32000-1 §7.3). It reads only what an
// incremental signature revision needs (trailer, Catalog, AcroForm, the first page, DSS, /Sig dictionaries);
// content streams are never interpreted. Taken from eid-mongolia-desktop (feat/macos-local-pades f1babff, byte-identical
// to the Go writer); reference = gerege-systems/eid-mongolia-sdk-go `pades` (digitorus/pdf reader).

/// Malformed or unsupported PDF input (encrypted, broken xref, …). Maps to the `pdf_invalid` message.
struct PdfError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

struct PdfRef: Hashable {
    let id: Int
    let gen: Int
}

/// A dictionary keeps its entries by name; serialisation sorts keys (digitorus `Value.Keys()` sorts).
struct PdfDict {
    var entries: [String: PdfObject] = [:]
    subscript(_ key: String) -> PdfObject { entries[key] ?? .null }
    /// Keys in byte order (Go `sort.Strings`); names hold one byte per scalar (Latin-1).
    var sortedKeys: [String] {
        entries.keys.sorted { a, b in
            a.unicodeScalars.map(\.value).lexicographicallyPrecedes(b.unicodeScalars.map(\.value))
        }
    }
}

indirect enum PdfObject {
    case null
    case bool(Bool)
    case int(Int64)
    case real(Double)
    /// Raw string bytes (literal escapes resolved / hex decoded).
    case string([UInt8])
    /// Name without the slash, one byte per scalar (#xx decoded).
    case name(String)
    case array([PdfObject])
    case dict(PdfDict)
    case ref(PdfRef)
    /// Stream dictionary + the raw (still encoded) data range in the reader's bytes.
    case stream(PdfDict, Range<Int>)

    var dict: PdfDict? {
        switch self {
        case .dict(let d), .stream(let d, _): return d
        default: return nil
        }
    }
    var array: [PdfObject]? { if case .array(let a) = self { return a }; return nil }
    var nameValue: String? { if case .name(let n) = self { return n }; return nil }
    var intValue: Int64? {
        switch self {
        case .int(let i): return i
        case .real(let r) where r == r.rounded() && abs(r) < 1e15: return Int64(r)
        default: return nil
        }
    }
    var isNull: Bool { if case .null = self { return true }; return false }
    var refValue: PdfRef? { if case .ref(let r) = self { return r }; return nil }

    /// PDF text string → String (UTF-16BE with BOM, else PDFDocEncoding ≈ Latin-1) — like digitorus `Text()`.
    var text: String {
        guard case .string(let b) = self else { return "" }
        if b.count >= 2, b[0] == 0xFE, b[1] == 0xFF {
            var units: [UInt16] = []
            var i = 2
            while i + 1 < b.count { units.append(UInt16(b[i]) << 8 | UInt16(b[i + 1])); i += 2 }
            return String(decoding: units, as: UTF16.self)
        }
        return String(b.map { Character(Unicode.Scalar($0)) })
    }
}

/// Tokeniser/parser over the file bytes.
struct PdfLexer {
    let b: [UInt8]
    var pos: Int

    init(_ bytes: [UInt8], at pos: Int = 0) { b = bytes; self.pos = pos }

    static func isWhite(_ c: UInt8) -> Bool { c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }
    static func isDelim(_ c: UInt8) -> Bool {
        c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B || c == 0x5D || c == 0x7B || c == 0x7D
            || c == 0x2F || c == 0x25
    }
    static func isRegular(_ c: UInt8) -> Bool { !isWhite(c) && !isDelim(c) }

    mutating func skipWhite() {
        while pos < b.count {
            let c = b[pos]
            if Self.isWhite(c) { pos += 1; continue }
            if c == 0x25 {                                    // % comment to end of line
                while pos < b.count, b[pos] != 10, b[pos] != 13 { pos += 1 }
                continue
            }
            break
        }
    }

    /// A bare keyword / number token (regular characters) without consuming it.
    func peekWord(at p: Int) -> (String, Int)? {
        var i = p
        while i < b.count, Self.isWhite(b[i]) { i += 1 }
        let s = i
        while i < b.count, Self.isRegular(b[i]) { i += 1 }
        guard i > s else { return nil }
        return (String(decoding: b[s..<i], as: UTF8.self), i)
    }

    mutating func word() -> String? {
        skipWhite()
        guard let (w, end) = peekWord(at: pos) else { return nil }
        pos = end
        return w
    }

    mutating func expect(_ keyword: String) throws {
        guard word() == keyword else { throw PdfError("expected \(keyword) at \(pos)") }
    }

    mutating func parseObject(depth: Int = 0) throws -> PdfObject {
        guard depth < 64 else { throw PdfError("nesting too deep") }
        skipWhite()
        guard pos < b.count else { throw PdfError("unexpected end of file") }
        let c = b[pos]
        switch c {
        case 0x2F: // name
            pos += 1
            var out = ""
            while pos < b.count, Self.isRegular(b[pos]) {
                var ch = b[pos]
                if ch == 0x23, pos + 2 < b.count, let hi = Self.hexVal(b[pos + 1]), let lo = Self.hexVal(b[pos + 2]) {
                    ch = hi << 4 | lo
                    pos += 2
                }
                out.unicodeScalars.append(Unicode.Scalar(ch))
                pos += 1
            }
            return .name(out)
        case 0x28:
            return .string(try literalString())
        case 0x3C:
            if pos + 1 < b.count, b[pos + 1] == 0x3C {
                pos += 2
                var d = PdfDict()
                while true {
                    skipWhite()
                    guard pos < b.count else { throw PdfError("unterminated dictionary") }
                    if b[pos] == 0x3E, pos + 1 < b.count, b[pos + 1] == 0x3E { pos += 2; break }
                    guard case .name(let key) = try parseObject(depth: depth + 1) else {
                        throw PdfError("dictionary key is not a name at \(pos)")
                    }
                    let value = try parseObject(depth: depth + 1)
                    if !value.isNull { d.entries[key] = value }   // null value = absent key (ISO 32000-1 §7.3.7)
                }
                return .dict(d)
            }
            return .string(try hexString())
        case 0x5B:
            pos += 1
            var a: [PdfObject] = []
            while true {
                skipWhite()
                guard pos < b.count else { throw PdfError("unterminated array") }
                if b[pos] == 0x5D { pos += 1; break }
                a.append(try parseObject(depth: depth + 1))
            }
            return .array(a)
        default:
            guard let w = word() else { throw PdfError("unexpected byte \(c) at \(pos)") }
            switch w {
            case "true": return .bool(true)
            case "false": return .bool(false)
            case "null": return .null
            default: break
            }
            if let i = Int64(w) {
                // "id gen R"
                let save = pos
                if i >= 0, let (g, e1) = peekWord(at: pos), let gen = Int(g), gen >= 0,
                   let (r, e2) = peekWord(at: e1), r == "R" {
                    _ = e1
                    pos = e2
                    return .ref(PdfRef(id: Int(i), gen: gen))
                }
                pos = save
                return .int(i)
            }
            if let r = Self.real(w) { return .real(r) }
            throw PdfError("unexpected token \(w) at \(pos)")
        }
    }

    static func real(_ w: String) -> Double? {
        guard w.contains("."), w.allSatisfy({ $0.isNumber || $0 == "." || $0 == "-" || $0 == "+" }) else { return nil }
        var s = w
        if s.hasPrefix(".") || s.hasPrefix("-.") || s.hasPrefix("+.") { s = s.replacingOccurrences(of: ".", with: "0.") }
        return Double(s)
    }

    static func hexVal(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }

    private mutating func hexString() throws -> [UInt8] {
        pos += 1
        var out: [UInt8] = []
        var hi: UInt8?
        while pos < b.count {
            let c = b[pos]
            pos += 1
            if c == 0x3E {
                if let h = hi { out.append(h << 4) }
                return out
            }
            if Self.isWhite(c) { continue }
            guard let v = Self.hexVal(c) else { throw PdfError("bad hex string") }
            if let h = hi { out.append(h << 4 | v); hi = nil } else { hi = v }
        }
        throw PdfError("unterminated hex string")
    }

    private mutating func literalString() throws -> [UInt8] {
        pos += 1
        var out: [UInt8] = []
        var depth = 1
        while pos < b.count {
            let c = b[pos]
            pos += 1
            switch c {
            case 0x5C: // backslash
                guard pos < b.count else { break }
                let e = b[pos]
                pos += 1
                switch e {
                case 0x6E: out.append(10)
                case 0x72: out.append(13)
                case 0x74: out.append(9)
                case 0x62: out.append(8)
                case 0x66: out.append(12)
                case 0x0D: if pos < b.count, b[pos] == 0x0A { pos += 1 }   // line continuation
                case 0x0A: break
                case 0x30...0x37:
                    var v = Int(e - 0x30)
                    for _ in 0..<2 where pos < b.count && (0x30...0x37).contains(b[pos]) {
                        v = v * 8 + Int(b[pos] - 0x30)
                        pos += 1
                    }
                    out.append(UInt8(v & 0xFF))
                default: out.append(e)                         // \( \) \\ and unknown escapes
                }
            case 0x28: depth += 1; out.append(c)
            case 0x29:
                depth -= 1
                if depth == 0 { return out }
                out.append(c)
            case 0x0D:                                          // EOL in a literal = LF
                if pos < b.count, b[pos] == 0x0A { pos += 1 }
                out.append(0x0A)
            default: out.append(c)
            }
        }
        throw PdfError("unterminated literal string")
    }
}
