import Foundation

/// One incremental update (revision): output = base + "\n" + new objects + xref + trailer; base bytes never
/// change. 1:1 port of the Go reference `pades/internal/core/incremental.go` + `serialize.go` (digitorus fork)
/// so the CA validator profile (internal/validate/revisions.go) accepts the result the same way. Written streams
/// (the xref stream here) are UNCOMPRESSED — cross-language byte identity (decision 2026-10-14 ~22:20).
final class PdfIncremental {
    struct Entry { let id: Int; let gen: Int; var offset: Int }

    let reader: PdfReader
    private(set) var out: [UInt8]
    private(set) var nextID: Int
    private var entries: [Entry] = []

    init(_ base: [UInt8]) throws {
        let r = try PdfReader(base)
        if !r.trailer["Encrypt"].isNull { throw PdfError("encrypted PDF") }
        guard case .dict = try r.resolve(r.trailer["Root"]) else { throw PdfError("Catalog missing") }
        guard let size = r.trailer["Size"].intValue, size > 0, size <= 1 << 23 else { throw PdfError("bad /Size") }
        reader = r
        nextID = max(Int(size), r.maxObjectID + 1)
        out = base
        out.reserveCapacity(base.count + 64 << 10)
        out.append(0x0A)                                   // empty line after %%EOF (digitorus)
    }

    var root: PdfDict { (try? reader.resolve(reader.trailer["Root"]).dict) ?? PdfDict() }
    var rootRef: PdfRef? { reader.trailer["Root"].refValue }

    func reserve() -> Int {
        defer { nextID += 1 }
        return nextID
    }

    /// Writes object `id gen`; returns the offset where its body starts.
    @discardableResult
    func writeObject(_ id: Int, gen: Int = 0, _ body: [UInt8]) -> Int {
        out.append(0x0A)
        entries.append(Entry(id: id, gen: gen, offset: out.count))
        out += Array("\(id) \(gen) obj\n".utf8)
        let start = out.count
        out += Self.trimSpace(body)
        out += Array("\nendobj\n".utf8)
        return start
    }

    @discardableResult
    func addObject(_ body: [UInt8]) -> (Int, Int) {
        let id = reserve()
        return (id, writeObject(id, body))
    }

    /// xref (same kind as the base's latest section) + trailer; `rootID` = the new Catalog.
    func finish(rootID: Int) throws -> [UInt8] {
        guard !entries.isEmpty else { throw PdfError("no new objects") }
        out.append(0x0A)
        let xrefStart = out.count
        var xid = 0
        if reader.xrefIsStream {
            xid = reserve()
            entries.append(Entry(id: xid, gen: 0, offset: xrefStart))
        }
        entries.sort { $0.id < $1.id }
        var runs: [(Int, Int)] = []
        for (i, e) in entries.enumerated() {
            if i > 0, e.id == entries[i - 1].id { throw PdfError("duplicate object number") }
            if i > 0, e.id == entries[i - 1].id + 1 { runs[runs.count - 1].1 += 1; continue }
            runs.append((i, 1))
        }
        let prev = reader.startXref
        var extra = ""
        switch reader.trailer["Info"] {
        case .ref(let info):
            if !((try? reader.object(info))?.isNull ?? true) { extra += " /Info \(info.id) \(info.gen) R" }
        case .dict:
            // Direct /Info (profile pades-client/1, P3): copied as is.
            extra += " /Info " + (try serialize(reader.trailer["Info"]))
        default:
            break
        }
        if case .array(let id)? = try? reader.resolve(reader.trailer["ID"]), id.count == 2,
           case .string(let a) = (try? reader.resolve(id[0])) ?? .null,
           case .string(let b) = (try? reader.resolve(id[1])) ?? .null {
            extra += " /ID [\(Self.hexString(a)) \(Self.hexString(b))]"
        }
        if !reader.xrefIsStream {
            out += Array("xref\n".utf8)
            for r in runs {
                out += Array("\(entries[r.0].id) \(r.1)\n".utf8)
                for e in entries[r.0..<(r.0 + r.1)] {
                    out += Array(String(format: "%010d %05d n\r\n", e.offset, e.gen).utf8)
                }
            }
            out += Array("trailer\n<< /Size \(nextID) /Root \(rootID) 0 R\(extra) /Prev \(prev) >>\nstartxref\n\(xrefStart)\n%%EOF\n".utf8)
            return out
        }
        var rows: [UInt8] = []
        for e in entries {
            guard e.offset <= Int(UInt32.max) else { throw PdfError("offset does not fit 4 bytes") }
            guard e.gen <= 0xFF else { throw PdfError("generation does not fit 1 byte") }
            rows.append(1)
            rows += [UInt8(e.offset >> 24 & 0xFF), UInt8(e.offset >> 16 & 0xFF), UInt8(e.offset >> 8 & 0xFF), UInt8(e.offset & 0xFF)]
            rows.append(UInt8(e.gen))
        }
        let index = runs.map { "\(entries[$0.0].id) \($0.1)" }.joined(separator: " ")
        out += Array("\(xid) 0 obj\n<< /Type /XRef /Length \(rows.count) /W [1 4 1] /Prev \(prev) /Size \(nextID) /Index [\(index)] /Root \(rootID) 0 R\(extra) >>\nstream\n".utf8)
        out += rows
        out += Array("\nendstream\nendobj\nstartxref\n\(xrefStart)\n%%EOF\n".utf8)
        return out
    }

    /// Catalog keys except /Type and `skip`, as "  /Key value\n" (digitorus createCatalog).
    func catalogCopy(skip: Set<String>) throws -> String {
        var s = ""
        let r = root
        for key in r.sortedKeys where key != "Type" && !skip.contains(key) {
            s += "  /\(Self.escapeName(key)) "
            s += try serialize(r[key])
            s += "\n"
        }
        return s
    }

    // MARK: - Serialisation (serialize.go)

    /// Direct values are rewritten; references stay "N G R" (a reference to a missing/null object → "null").
    /// Strings as hex, names #xx-escaped, reals without exponent.
    func serialize(_ v: PdfObject, depth: Int = 0) throws -> String {
        guard depth <= 32 else { throw PdfError("value nested too deep") }
        switch v {
        case .null: return "null"
        case .ref(let r):
            if case .null = try reader.object(r) { return "null" }
            return "\(r.id) \(r.gen) R"
        case .string(let b): return Self.hexString(b)
        case .bool(let b): return b ? "true" : "false"
        case .int(let i): return String(i)
        case .real(let d): return Self.formatReal(d)
        case .name(let n): return "/" + Self.escapeName(n)
        case .dict(let d):
            var s = "<<"
            for key in d.sortedKeys {
                s += " /" + Self.escapeName(key) + " "
                s += try serialize(d[key], depth: depth + 1)
            }
            return s + " >>"
        case .array(let a):
            return "[" + (try a.map { try serialize($0, depth: depth + 1) }).joined(separator: " ") + "]"
        case .stream:
            throw PdfError("cannot copy a direct stream")
        }
    }

    static func hexString(_ raw: [UInt8]) -> String {
        "<" + raw.map { String(format: "%02x", $0) }.joined() + ">"
    }

    static func escapeName(_ n: String) -> String {
        var s = ""
        for u in n.unicodeScalars {
            let c = u.value
            if c < 0x21 || c > 0x7E || "#()<>[]{}/%".unicodeScalars.contains(u) {
                s += String(format: "#%02X", c & 0xFF)
            } else {
                s.unicodeScalars.append(u)
            }
        }
        return s
    }

    /// Go strconv.FormatFloat(f, 'f', -1, 64): shortest round-trip digits, never an exponent.
    static func formatReal(_ d: Double) -> String {
        if d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
        let s = "\(d)"
        if s.contains("e") || s.contains("E"), let dec = Decimal(string: s) { return "\(dec)" }
        return s
    }

    static func trimSpace(_ b: [UInt8]) -> [UInt8] {
        var lo = 0, hi = b.count
        func ws(_ c: UInt8) -> Bool { c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32 }
        while lo < hi, ws(b[lo]) { lo += 1 }
        while hi > lo, ws(b[hi - 1]) { hi -= 1 }
        return Array(b[lo..<hi])
    }
}
