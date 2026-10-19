import Foundation
import zlib

/// PRECHECKS #2a / #2b — Go reference `validate.CheckStructure` (nesting.go + objstm.go), run before any PDF parsing:
/// array/dictionary nesting > 256 from every point where a reader may start an object (after the `obj` / `trailer`
/// keywords, at every offset of a /Type /ObjStm header), a read/inflate budget, top-level /Size > 2 097 152, and the
/// object-stream graph (a container that is itself in an object stream, header references into object streams,
/// /Extends cycles or chains > 64). Same rules on every SDK so a document gets the same answer (golden validate/v4
/// `deep-nesting*`). One layer of defence — it does not make untrusted PDF parsing safe on its own.
enum Structure {
    struct Failure: Error, CustomStringConvertible {
        var description: String { "PDF structure nested too deep or too complex" }
    }

    static let maxNesting = 256
    static let scanFactor = 16              // read budget = 16 × len(doc) + 1 MiB
    static let maxObjStmBytes = 32 << 20    // all inflated object streams together (zip bomb)
    static let maxXrefSize: Int64 = 1 << 21
    static let maxObjStmChain = 64

    static func check(_ doc: [UInt8]) throws {
        var s = Scan(budget: scanFactor * doc.count + (1 << 20), inflateLeft: maxObjStmBytes, encrypted: hasEncryptRef(doc))
        for kw in [Array("obj".utf8), Array("trailer".utf8)] {
            var k = 0
            while let at = find(kw, in: doc, from: k) {
                let end = at + kw.count
                k = end
                // The keyword stands alone (`endobj`, `objx` are other keywords).
                if at > 0, !isSpace(doc[at - 1]), !isDelim(doc[at - 1]) { continue }
                if end < doc.count, !isSpace(doc[end]), !isDelim(doc[end]) { continue }
                try s.object(doc[...], end, allowStream: true)
            }
        }
        if s.bigSize { throw Failure() }
        try checkObjStmGraph(doc)
    }

    /// `/Encrypt` followed by an indirect reference (`N G R`) or a direct dictionary (`<<`) — Go regexp
    /// `/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)` (`\s` = [\t\n\f\r ]); `/EncryptMetadata` does not count.
    static func hasEncryptRef(_ b: [UInt8]) -> Bool {
        let key = Array("/Encrypt".utf8)
        func ws(_ c: UInt8) -> Bool { c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }
        func digit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
        var from = 0
        while let k = find(key, in: b, from: from) {
            from = k + 1
            var p = k + key.count
            var q = p
            while q < b.count, ws(b[q]) { q += 1 }
            if q + 1 < b.count, b[q] == 0x3C, b[q + 1] == 0x3C { return true }
            // \s+\d+\s+\d+\s+R
            var ok = true
            for _ in 0..<2 {
                let w = p
                while p < b.count, ws(b[p]) { p += 1 }
                let d = p
                while p < b.count, digit(b[p]) { p += 1 }
                if p == d || d == w { ok = false; break }
            }
            if ok {
                let w = p
                while p < b.count, ws(b[p]) { p += 1 }
                if p > w, p < b.count, b[p] == 0x52 { return true }
            }
        }
        return false
    }

    static func find(_ needle: [UInt8], in b: [UInt8], from: Int) -> Int? {
        guard let first = needle.first, needle.count <= b.count else { return nil }
        var i = from
        let last = b.count - needle.count
        while i <= last {
            if b[i] == first {
                var j = 1
                while j < needle.count, b[i + j] == needle[j] { j += 1 }
                if j == needle.count { return i }
            }
            i += 1
        }
        return nil
    }

    static func isSpace(_ c: UInt8) -> Bool { c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32 }
    // ()<>[]{}/%
    static func isDelim(_ c: UInt8) -> Bool {
        c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B || c == 0x5D || c == 0x7B || c == 0x7D || c == 0x2F || c == 0x25
    }

    // MARK: - Lexer (digitorus buffer.readToken, structure only)

    enum Tok { case eof, err, arr, arrEnd, dict, dictEnd, name, word, str }

    struct Lex {
        let b: ArraySlice<UInt8>
        var pos: Int
        var val = ""

        init(_ b: ArraySlice<UInt8>, _ pos: Int) { self.b = b; self.pos = pos }

        mutating func next() -> Tok {
            while true {
                while pos < b.endIndex, isSpace(b[pos]) { pos += 1 }
                if pos < b.endIndex, b[pos] == 0x25 {
                    while pos < b.endIndex, b[pos] != 0x0D, b[pos] != 0x0A { pos += 1 }
                    continue
                }
                break
            }
            guard pos < b.endIndex else { return .eof }
            let c = b[pos]
            pos += 1
            switch c {
            case 0x3C:
                if pos < b.endIndex, b[pos] == 0x3C { pos += 1; return .dict }
                while pos < b.endIndex, b[pos] != 0x3E { pos += 1 }
                pos += 1
                return .str
            case 0x28:
                var depth = 1
                while pos < b.endIndex, depth > 0 {
                    switch b[pos] {
                    case 0x28: depth += 1
                    case 0x29: depth -= 1
                    case 0x5C: pos += 1
                    default: break
                    }
                    pos += 1
                }
                return .str
            case 0x5B: return .arr
            case 0x5D: return .arrEnd
            case 0x7B, 0x7D:
                val = String(UnicodeScalar(c))
                return .word
            case 0x2F:
                var name: [UInt8] = []
                while pos < b.endIndex, !isDelim(b[pos]), !isSpace(b[pos]) {
                    if b[pos] == 0x23, pos + 2 < b.endIndex, let hi = PdfLexer.hexVal(b[pos + 1]), let lo = PdfLexer.hexVal(b[pos + 2]) {
                        name.append(hi << 4 | lo)
                        pos += 3
                        continue
                    }
                    name.append(b[pos])
                    pos += 1
                }
                val = String(name.map { Character(UnicodeScalar($0)) })
                return .name
            case 0x3E:
                if pos < b.endIndex, b[pos] == 0x3E { pos += 1; return .dictEnd }
                return .err
            case 0x29:
                return .err
            default:
                let start = pos - 1
                while pos < b.endIndex, !isDelim(b[pos]), !isSpace(b[pos]) { pos += 1 }
                val = String(b[start..<pos].map { Character(UnicodeScalar($0)) })
                return .word
            }
        }
    }

    /// Go `strconv.ParseInt(s, 10, 64)` succeeds.
    static func isInt(_ s: String) -> Bool { Int64(s) != nil }

    /// Go `v, _ := strconv.ParseInt(s, 10, 64)`: syntax error → 0, out of range → ±MaxInt64.
    static func parseInt64(_ s: String) -> Int64 {
        if let v = Int64(s) { return v }
        let digits = s.drop { $0 == "+" || $0 == "-" }
        guard s.count - digits.count <= 1, !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return 0 }
        return s.hasPrefix("-") ? Int64.min : Int64.max
    }

    struct Frame {
        var dict: Bool
        var expectKey: Bool
        var key = ""
    }

    struct Info {
        var typ = "", filter = ""
        var filters = 0
        var parms = false
        var indirect = false
        var first: Int64 = 0, nCount: Int64 = 0
    }

    struct Scan {
        var budget: Int
        var inflateLeft: Int
        let encrypted: Bool
        var bigSize = false

        init(budget: Int, inflateLeft: Int, encrypted: Bool) {
            self.budget = budget
            self.inflateLeft = inflateLeft
            self.encrypted = encrypted
        }

        /// One reader object at `start` (a doubled `N G obj` included), depth-checked; with `allowStream` a top-level
        /// /Type /ObjStm dictionary's stream is inflated and its objects checked.
        mutating func object(_ b: ArraySlice<UInt8>, _ start: Int, allowStream: Bool) throws {
            var l = Lex(b, start)
            defer { budget -= l.pos - start }
            var stack: [Frame] = []
            var info = Info()
            while true {
                if budget - (l.pos - start) < 0 { throw Failure() }
                let tok = l.next()
                if let top = stack.last, top.dict, top.expectKey {
                    switch tok {
                    case .dictEnd:
                        stack.removeLast()
                        if stack.isEmpty {
                            if allowStream, info.typ == "ObjStm" || info.indirect { try objStm(b, &l, info) }
                            return
                        }
                        stack[stack.count - 1].expectKey = stack[stack.count - 1].dict
                        continue
                    case .name:
                        stack[stack.count - 1].key = l.val
                        stack[stack.count - 1].expectKey = false
                        continue
                    default:
                        return  // non-name key — the reader fails here
                    }
                }
                switch tok {
                case .eof, .err, .dictEnd:
                    return
                case .arr, .dict:
                    if stack.count >= maxNesting { throw Failure() }
                    if stack.count == 1, stack[0].dict, stack[0].key == "DecodeParms" { info.parms = true }
                    stack.append(Frame(dict: tok == .dict, expectKey: tok == .dict))
                    continue
                case .arrEnd:
                    guard let top = stack.last, !top.dict else { return }
                    stack.removeLast()
                case .word:
                    var done = false
                    if isInt(l.val) {
                        let save = l.pos, saveVal = l.val
                        if l.next() == .word, isInt(l.val) {
                            let t3 = l.next()
                            if t3 == .word, l.val == "R" {
                                if stack.count == 1, stack[0].dict,
                                   ["Type", "Filter", "DecodeParms", "N", "First"].contains(stack[0].key) {
                                    info.indirect = true
                                }
                                done = true  // a reference = one value
                            } else if t3 == .word, l.val == "obj" {
                                continue     // doubled `N G obj` — the next value continues this object
                            }
                        }
                        if !done {
                            l.pos = save
                            l.val = saveVal
                        }
                    }
                    if !done { noteScalar(stack, &info, tok, l.val) }
                case .name, .str:
                    noteScalar(stack, &info, tok, l.val)
                }
                if stack.isEmpty { return }
                if stack[stack.count - 1].dict { stack[stack.count - 1].expectKey = true }
            }
        }

        mutating func noteScalar(_ stack: [Frame], _ info: inout Info, _ tok: Tok, _ val: String) {
            if stack.count == 1, stack[0].dict {
                switch stack[0].key {
                case "Type": if tok == .name { info.typ = val }
                case "Filter": if tok == .name { info.filter = val; info.filters = 1 }
                case "DecodeParms": if !(tok == .word && val == "null") { info.parms = true }
                case "N": info.nCount = parseInt64(val)
                case "Size": if tok == .word, let n = Int64(val), n > maxXrefSize { bigSize = true }
                case "First": info.first = parseInt64(val)
                default: break
                }
            } else if stack.count == 2, stack[0].dict, stack[0].key == "Filter", !stack[1].dict, tok == .name {
                info.filter = val
                info.filters += 1
            }
        }

        /// The data after `stream` (FlateDecode ends on its own, whatever /Length says), objects at every header offset.
        mutating func objStm(_ b: ArraySlice<UInt8>, _ l: inout Lex, _ info: Info) throws {
            guard l.next() == .word, l.val == "stream", !encrypted else { return }
            if info.indirect { throw Failure() }  // /Type /Filter /N /First by reference — never in a legitimate file
            guard info.typ == "ObjStm" else { return }
            var p = l.pos
            if p < b.endIndex, b[p] == 0x0D { p += 1 }
            if p < b.endIndex, b[p] == 0x0A { p += 1 }
            if info.filters == 0 {
                try objStmData(b[min(p, b.endIndex)...], info)  // unfiltered — the rest of the file
                return
            }
            guard info.filters == 1, info.filter == "FlateDecode" else { return }  // the reader does not decode it
            if info.parms { throw Failure() }  // predictor object streams are not replayed — fail closed
            let (data, over) = inflatePrefix(b[min(p, b.endIndex)...], limit: inflateLeft)
            if over { throw Failure() }
            inflateLeft -= data.count
            budget -= data.count
            try objStmData(data[...], info)
        }

        mutating func objStmData(_ data: ArraySlice<UInt8>, _ info: Info) throws {
            var l = Lex(data, data.startIndex)
            var i: Int64 = 0
            while i < info.nCount {
                i += 1
                if l.next() == .eof { break }
                guard l.next() == .word, let off = Int64(l.val) else { continue }
                guard info.first >= 0, off >= 0, info.first <= Int64(data.count), off < Int64(data.count) - info.first else { continue }
                if budget < 0 { throw Failure() }
                try object(data, data.startIndex + Int(info.first + off), allowStream: false)
            }
            if budget < 0 { throw Failure() }
        }
    }

    /// zlib-inflates the prefix of `input` (stops at the end of the zlib stream or at the first error, keeping what was
    /// produced — Go `io.ReadAll(zlib.NewReader)`); `over` when more than `limit` bytes come out.
    static func inflatePrefix(_ input: ArraySlice<UInt8>, limit: Int) -> ([UInt8], Bool) {
        var s = z_stream()
        guard inflateInit_(&s, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return ([], false) }
        defer { inflateEnd(&s) }
        var out: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 << 10)
        var src = Array(input)
        var over = false
        src.withUnsafeMutableBufferPointer { inBuf in
            s.next_in = inBuf.baseAddress
            s.avail_in = uInt(inBuf.count)
            while true {
                let rc = chunk.withUnsafeMutableBufferPointer { outBuf -> Int32 in
                    s.next_out = outBuf.baseAddress
                    s.avail_out = uInt(outBuf.count)
                    return zlib.inflate(&s, Z_NO_FLUSH)
                }
                out.append(contentsOf: chunk[0..<(chunk.count - Int(s.avail_out))])
                if out.count > limit { over = true; return }
                if rc != Z_OK { return }
            }
        }
        return (out, over)
    }

    // MARK: - Object-stream graph (PRECHECKS #2b)

    /// Go `checkObjStmGraph`: an object's container stream must not itself be in an object stream; the container's
    /// (and its /Extends chain's) header must not reference objects inside object streams; /Extends must not cycle or
    /// exceed 64. A reader that cannot open or parse the document is not judged here (the caller reports PDF_INVALID).
    static func checkObjStmGraph(_ doc: [UInt8]) throws {
        guard let r = try? PdfReader(doc) else { return }
        let xr = r.xref
        func registered(_ p: PdfRef) -> Bool {
            switch xr[p.id] {
            case .offset(_, let g)?: return g == p.gen
            case .compressed?: return p.gen == 0
            case nil: return false
            }
        }
        func inStream(_ p: PdfRef) -> Bool {
            if case .compressed? = xr[p.id] { return registered(p) }
            return false
        }
        var containers = Set<Int>()
        for (_, e) in xr {
            guard case .compressed(let stm, _) = e else { continue }
            if inStream(PdfRef(id: stm, gen: 0)) { throw Failure() }
            containers.insert(stm)
        }
        for c in containers.sorted() {
            var seen = Set<PdfRef>()
            var p = PdfRef(id: c, gen: 0)
            while registered(p) {
                if seen.contains(p) || seen.count > maxObjStmChain { throw Failure() }
                seen.insert(p)
                guard case .offset(let off, _)? = xr[p.id] else { break }
                guard let (hdr, isStream) = r.rawHeader(at: off, id: p.id) else { return }
                guard isStream else { break }
                var bad = false
                walkRefs(.dict(hdr), 0) { bad = bad || inStream($0) }
                if bad { throw Failure() }
                guard case .ref(let ext) = hdr["Extends"] else { break }
                p = ext
            }
        }
    }

    static func walkRefs(_ v: PdfObject, _ depth: Int, _ fn: (PdfRef) -> Void) {
        guard depth <= maxNesting else { return }
        switch v {
        case .ref(let r): fn(r)
        case .dict(let d), .stream(let d, _): for x in d.entries.values { walkRefs(x, depth + 1, fn) }
        case .array(let a): for x in a { walkRefs(x, depth + 1, fn) }
        default: break
        }
    }
}
