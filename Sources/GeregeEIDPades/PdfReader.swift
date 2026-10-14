import Foundation
import zlib

/// Reads the cross-reference structure of a PDF (classic tables, xref streams, hybrid files, object streams)
/// and resolves indirect objects. Equivalent to the subset of digitorus/pdf the CA's PAdES writer uses.
final class PdfReader {
    enum XrefEntry {
        case offset(Int, gen: Int)
        case compressed(stream: Int, index: Int)
    }

    let bytes: [UInt8]
    /// Header version, e.g. "1.3".
    let version: String
    /// Latest trailer (for an xref stream: its dictionary).
    let trailer: PdfDict
    /// `startxref` of the file — the new revision's /Prev.
    let startXref: Int
    /// The latest xref section is a stream (the new revision writes the same kind).
    let xrefIsStream: Bool
    private(set) var xref: [Int: XrefEntry] = [:]
    private var cache: [PdfRef: PdfObject] = [:]
    private var objStmCache: [Int: (first: Int, offsets: [(Int, Int)], data: [UInt8])] = [:]

    var maxObjectID: Int { xref.keys.max() ?? 0 }

    init(_ data: [UInt8]) throws {
        bytes = data
        version = Self.headerVersion(data)
        guard let sx = Self.findStartXref(data) else { throw PdfError("startxref not found") }
        startXref = sx
        var seen = Set<Int>()
        var offset: Int? = sx
        var first: (PdfDict, Bool)?
        var entries: [Int: XrefEntry] = [:]
        while let off = offset {
            guard !seen.contains(off), seen.count < 512, off >= 0, off < data.count else {
                if seen.contains(off) { break }
                throw PdfError("bad xref offset")
            }
            seen.insert(off)
            let (dict, isStream, sectionEntries) = try Self.readSection(data, at: off)
            if first == nil { first = (dict, isStream) }
            // Hybrid file: the table's /XRefStm entries come right after the table's own.
            var merged = sectionEntries
            if !isStream, let stmOff = dict["XRefStm"].intValue, !seen.contains(Int(stmOff)) {
                seen.insert(Int(stmOff))
                if let (_, _, extra) = try? Self.readSection(data, at: Int(stmOff)) {
                    for (k, v) in extra where merged[k] == nil { merged[k] = v }
                }
            }
            for (k, v) in merged where entries[k] == nil { entries[k] = v }
            offset = dict["Prev"].intValue.map(Int.init)
        }
        guard let (tr, isStream) = first else { throw PdfError("no xref") }
        trailer = tr
        xrefIsStream = isStream
        xref = entries
    }

    // MARK: - Structure

    static func headerVersion(_ b: [UInt8]) -> String {
        let marker = Array("%PDF-".utf8)
        let limit = min(b.count, 1024)
        guard limit >= marker.count, let at = b[0..<limit].firstRange(of: marker) else { return "" }
        var i = at.upperBound
        var s = ""
        while i < limit, (b[i] >= 0x30 && b[i] <= 0x39) || b[i] == 0x2E { s.append(Character(Unicode.Scalar(b[i]))); i += 1 }
        return s
    }

    static func findStartXref(_ b: [UInt8]) -> Int? {
        let key = Array("startxref".utf8)
        let from = max(0, b.count - 2048)
        var i = b.count - key.count
        while i >= from {
            if b[i] == key[0], Array(b[i..<(i + key.count)]) == key {
                var lx = PdfLexer(b, at: i + key.count)
                return lx.word().flatMap(Int.init)
            }
            i -= 1
        }
        return nil
    }

    /// One xref section (table + trailer, or xref stream) at `off`.
    private static func readSection(_ b: [UInt8], at off: Int) throws -> (PdfDict, Bool, [Int: XrefEntry]) {
        var lx = PdfLexer(b, at: off)
        lx.skipWhite()
        if let (w, end) = lx.peekWord(at: lx.pos), w == "xref" {
            lx.pos = end
            var out: [Int: XrefEntry] = [:]
            while true {
                lx.skipWhite()
                guard let (w2, _) = lx.peekWord(at: lx.pos) else { throw PdfError("bad xref table") }
                if w2 == "trailer" { _ = lx.word(); break }
                guard let start = Int(lx.word() ?? ""), let count = Int(lx.word() ?? ""), count >= 0, count < 1 << 23 else {
                    throw PdfError("bad xref subsection")
                }
                for k in 0..<count {
                    guard let o = Int(lx.word() ?? ""), let g = Int(lx.word() ?? ""), let t = lx.word() else {
                        throw PdfError("bad xref entry")
                    }
                    let id = start + k
                    if t == "n", out[id] == nil, o > 0 { out[id] = .offset(o, gen: g) }
                }
            }
            guard case .dict(let tr) = try lx.parseObject() else { throw PdfError("bad trailer") }
            return (tr, false, out)
        }
        // xref stream object
        let reader = try PdfReader.bare(b)
        let obj = try reader.parseIndirect(at: off, expect: nil)
        guard case .stream(let d, _) = obj, d["Type"].nameValue == "XRef" else { throw PdfError("xref stream expected") }
        let raw = try reader.decodedStream(obj)
        guard let w = d["W"].array?.compactMap(\.intValue).map(Int.init), w.count == 3, w.allSatisfy({ $0 >= 0 && $0 <= 8 }),
              let size = d["Size"].intValue else { throw PdfError("bad xref stream") }
        var index = d["Index"].array?.compactMap(\.intValue).map(Int.init) ?? [0, Int(size)]
        if index.count % 2 != 0 { index.removeLast() }
        let rowLen = w.reduce(0, +)
        guard rowLen > 0 else { throw PdfError("bad xref stream /W") }
        var out: [Int: XrefEntry] = [:]
        var p = 0
        func field(_ n: Int, def: Int) -> Int {
            guard n > 0 else { return def }
            var v = 0
            for _ in 0..<n { v = v << 8 | Int(raw[p]); p += 1 }
            return v
        }
        for pair in stride(from: 0, to: index.count, by: 2) {
            let start = index[pair], count = index[pair + 1]
            for k in 0..<count {
                guard p + rowLen <= raw.count else { break }
                let type = field(w[0], def: 1), f2 = field(w[1], def: 0), f3 = field(w[2], def: 0)
                let id = start + k
                guard out[id] == nil else { continue }
                switch type {
                case 1: if f2 > 0 { out[id] = .offset(f2, gen: f3) }
                case 2: out[id] = .compressed(stream: f2, index: f3)
                default: break
                }
            }
        }
        return (d, true, out)
    }

    /// A reader with no xref (used to parse an xref stream object by offset).
    private init(bare b: [UInt8]) {
        bytes = b; version = ""; trailer = PdfDict(); startXref = 0; xrefIsStream = false
    }
    private static func bare(_ b: [UInt8]) throws -> PdfReader { PdfReader(bare: b) }

    // MARK: - Objects

    /// The object a reference points to; `.null` when it does not exist (ISO 32000-1 §7.3.10).
    func object(_ ref: PdfRef) throws -> PdfObject {
        if let hit = cache[ref] { return hit }
        guard let entry = xref[ref.id] else { return .null }
        let obj: PdfObject
        switch entry {
        case .offset(let off, let gen):
            guard gen == ref.gen else { return .null }
            obj = try parseIndirect(at: off, expect: ref.id)
        case .compressed(let stm, let idx):
            guard ref.gen == 0 else { return .null }
            obj = try objectFromStream(stm, index: idx, id: ref.id)
        }
        cache[ref] = obj
        return obj
    }

    /// Follows references (bounded).
    func resolve(_ o: PdfObject) throws -> PdfObject {
        var cur = o
        var n = 0
        while case .ref(let r) = cur {
            n += 1
            guard n < 16 else { throw PdfError("reference loop") }
            cur = try object(r)
        }
        return cur
    }

    /// `dict[key]` resolved.
    func get(_ d: PdfDict, _ key: String) throws -> PdfObject { try resolve(d[key]) }

    fileprivate func parseIndirect(at off: Int, expect id: Int?) throws -> PdfObject {
        guard off >= 0, off < bytes.count else { throw PdfError("object offset out of range") }
        var lx = PdfLexer(bytes, at: off)
        guard let n = Int(lx.word() ?? ""), Int(lx.word() ?? "") != nil else { throw PdfError("bad object header at \(off)") }
        if let id, n != id { throw PdfError("object \(id) not at its xref offset") }
        try lx.expect("obj")
        let obj = try lx.parseObject()
        guard case .dict(let d) = obj else { return obj }
        lx.skipWhite()
        guard let (w, end) = lx.peekWord(at: lx.pos), w == "stream" else { return obj }
        var start = end
        if start < bytes.count, bytes[start] == 0x0D { start += 1 }
        if start < bytes.count, bytes[start] == 0x0A { start += 1 }
        var length = -1
        if let l = d["Length"].intValue { length = Int(l) }
        else if case .ref(let r) = d["Length"], let l = try? resolve(.ref(r)).intValue { length = Int(l) }
        if length >= 0, start + length <= bytes.count, Self.endstreamFollows(bytes, at: start + length) {
            return .stream(d, start..<(start + length))
        }
        // Wrong /Length: up to "endstream".
        let key = Array("endstream".utf8)
        guard let r = bytes[start...].firstRange(of: key) else { throw PdfError("endstream not found") }
        var e = r.lowerBound
        if e > start, bytes[e - 1] == 0x0A { e -= 1 }
        if e > start, bytes[e - 1] == 0x0D { e -= 1 }
        return .stream(d, start..<e)
    }

    private static func endstreamFollows(_ b: [UInt8], at p: Int) -> Bool {
        var lx = PdfLexer(b, at: p)
        return lx.word() == "endstream"
    }

    private func objectFromStream(_ stm: Int, index: Int, id: Int) throws -> PdfObject {
        if objStmCache[stm] == nil {
            let s = try object(PdfRef(id: stm, gen: 0))
            guard case .stream(let d, _) = s, d["Type"].nameValue == "ObjStm",
                  let n = d["N"].intValue, let first = d["First"].intValue, n >= 0, n < 1 << 20 else {
                throw PdfError("bad object stream \(stm)")
            }
            let data = try decodedStream(s)
            var lx = PdfLexer(data)
            var offsets: [(Int, Int)] = []
            for _ in 0..<n {
                guard let oid = Int(lx.word() ?? ""), let o = Int(lx.word() ?? "") else { throw PdfError("bad object stream header") }
                offsets.append((oid, o))
            }
            objStmCache[stm] = (Int(first), offsets, data)
        }
        guard let entry = objStmCache[stm], index >= 0, index < entry.offsets.count, entry.offsets[index].0 == id else {
            throw PdfError("object \(id) not in object stream \(stm)")
        }
        var lx = PdfLexer(entry.data, at: entry.first + entry.offsets[index].1)
        return try lx.parseObject()
    }

    // MARK: - Stream data

    /// Decoded data of a stream (FlateDecode with PNG predictors, or unfiltered).
    func decodedStream(_ s: PdfObject) throws -> [UInt8] {
        guard case .stream(let d, let range) = s else { throw PdfError("not a stream") }
        var data = Array(bytes[range])
        let filters: [PdfObject]
        switch try resolve(d["Filter"]) {
        case .null: filters = []
        case .name(let n): filters = [.name(n)]
        case .array(let a): filters = a
        default: throw PdfError("bad /Filter")
        }
        var parms: [PdfObject]
        switch try resolve(d["DecodeParms"]) {
        case .array(let a): parms = a
        case .dict(let p): parms = [.dict(p)]
        default: parms = []
        }
        for (i, f) in filters.enumerated() {
            guard f.nameValue == "FlateDecode" || f.nameValue == "Fl" else {
                throw PdfError("unsupported filter \(f.nameValue ?? "?")")
            }
            data = try Zlib.inflate(data)
            if i < parms.count, let p = try resolve(parms[i]).dict {
                data = try Self.unpredict(data, p)
            }
        }
        return data
    }

    private static func unpredict(_ data: [UInt8], _ p: PdfDict) throws -> [UInt8] {
        let predictor = Int(p["Predictor"].intValue ?? 1)
        guard predictor >= 10 else {
            if predictor == 1 { return data }
            throw PdfError("unsupported predictor \(predictor)")
        }
        let colors = Int(p["Colors"].intValue ?? 1), bpc = Int(p["BitsPerComponent"].intValue ?? 8)
        let columns = Int(p["Columns"].intValue ?? 1)
        let bpp = max(1, colors * bpc / 8)
        let rowLen = (colors * bpc * columns + 7) / 8
        guard rowLen > 0 else { throw PdfError("bad predictor parameters") }
        var out: [UInt8] = []
        out.reserveCapacity(data.count)
        var prev = [UInt8](repeating: 0, count: rowLen)
        var i = 0
        while i + 1 + rowLen <= data.count {
            let type = data[i]
            var row = Array(data[(i + 1)..<(i + 1 + rowLen)])
            for x in 0..<rowLen {
                let a = x >= bpp ? Int(row[x - bpp]) : 0
                let b = Int(prev[x])
                let c = x >= bpp ? Int(prev[x - bpp]) : 0
                let add: Int
                switch type {
                case 0: add = 0
                case 1: add = a
                case 2: add = b
                case 3: add = (a + b) / 2
                case 4:
                    let pp = a + b - c, pa = abs(pp - a), pb = abs(pp - b), pc = abs(pp - c)
                    add = (pa <= pb && pa <= pc) ? a : (pb <= pc ? b : c)
                default: throw PdfError("bad PNG predictor row")
                }
                row[x] = UInt8((Int(row[x]) + add) & 0xFF)
            }
            out.append(contentsOf: row)
            prev = row
            i += 1 + rowLen
        }
        return out
    }
}

/// zlib (RFC 1950) inflate via the system libz (reading only — written streams are uncompressed, decision 2026-10-14).
enum Zlib {
    static func inflate(_ input: [UInt8], limit: Int = 64 << 20) throws -> [UInt8] {
        var s = z_stream()
        guard inflateInit_(&s, zlibVersion(), Int32(MemoryLayout<z_stream>.size)) == Z_OK else { throw PdfError("inflateInit") }
        defer { inflateEnd(&s) }
        var out: [UInt8] = []
        var chunk = [UInt8](repeating: 0, count: 64 << 10)
        var src = input
        let status: Int32 = src.withUnsafeMutableBufferPointer { inBuf -> Int32 in
            s.next_in = inBuf.baseAddress
            s.avail_in = uInt(inBuf.count)
            var rc: Int32 = Z_OK
            repeat {
                rc = chunk.withUnsafeMutableBufferPointer { outBuf -> Int32 in
                    s.next_out = outBuf.baseAddress
                    s.avail_out = uInt(outBuf.count)
                    return zlib.inflate(&s, Z_NO_FLUSH)
                }
                let produced = chunk.count - Int(s.avail_out)
                out.append(contentsOf: chunk[0..<produced])
                if out.count > limit { return Z_MEM_ERROR }
                if rc == Z_BUF_ERROR && s.avail_in == 0 { return Z_STREAM_END }   // truncated: keep what we have
            } while rc == Z_OK
            return rc
        }
        guard status == Z_STREAM_END else { throw PdfError("FlateDecode failed (\(status))") }
        return out
    }
}
