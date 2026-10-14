import CryptoKit
import Foundation

/// LTV data revision (/DSS). Port of the Go reference `pades/internal/core/dss.go`; DSS streams are written
/// uncompressed (as in Go).
enum PadesDSS {
    struct Material {
        var certs: [[UInt8]] = []
        var ocsps: [[UInt8]] = []
        var crls: [[UInt8]] = []
        /// The signature's /Contents exactly as a viewer reads it (hex-decoded, zero padding included —
        /// `PadesSignature.signatureContents`). VRI key = upper-hex SHA-1 of it (ISO 32000-2 §12.8.4.4). Empty = no VRI.
        var contents: [UInt8] = []
    }

    /// Old DSS streams larger than this are not read for de-duplication.
    private static let maxStream = 4 << 20

    /// Appends a signature-less revision with a new /DSS (old entries kept, byte-identical streams reused) + Catalog.
    static func append(_ signed: [UInt8], _ m: Material) throws -> [UInt8] {
        guard !(m.certs.isEmpty && m.ocsps.isEmpty && m.crls.isEmpty) else { throw PdfError("DSS is empty") }
        let inc = try PdfIncremental(signed)
        let r = inc.reader
        let old = try r.resolve(inc.root["DSS"])
        if !old.isNull, old.dict == nil { throw PdfError("/DSS is not a dictionary") }
        let oldDict = old.dict ?? PdfDict()
        var known: [[UInt8]: String] = [:]     // sha256(content) → reference
        var lists: [String: [String]] = [:]
        for key in ["Certs", "OCSPs", "CRLs"] {
            for e in try r.resolve(oldDict[key]).array ?? [] {
                let ref = try inc.serialize(e)
                lists[key, default: []].append(ref)
                let v = try r.resolve(e)
                if case .stream(_, let range) = v, range.count <= maxStream, let data = try? r.decodedStream(v) {
                    known[Array(SHA256.hash(data: data))] = ref
                }
            }
        }
        var vri: [[String]] = [[], [], []]
        func add(_ slot: Int, _ key: String, _ items: [[UInt8]]) {
            for der in items {
                let sum = Array(SHA256.hash(data: der))
                var ref = known[sum]
                if ref == nil {
                    let body = Array("<< /Length \(der.count) >>\nstream\n".utf8) + der + Array("\nendstream".utf8)
                    let (id, _) = inc.addObject(body)
                    ref = "\(id) 0 R"
                    known[sum] = ref
                    lists[key, default: []].append(ref!)
                }
                if !vri[slot].contains(ref!) { vri[slot].append(ref!) }
            }
        }
        add(0, "Certs", m.certs)
        add(1, "OCSPs", m.ocsps)
        add(2, "CRLs", m.crls)

        var dss = "<<"
        for key in ["Certs", "OCSPs", "CRLs"] where !(lists[key] ?? []).isEmpty {
            dss += " /\(key) [" + lists[key]!.joined(separator: " ") + "]"
        }
        let oldVRI = try r.resolve(oldDict["VRI"])
        if !m.contents.isEmpty || oldVRI.dict != nil {
            dss += " /VRI <<"
            var newKey = ""
            if !m.contents.isEmpty {
                newKey = Insecure.SHA1.hash(data: m.contents).map { String(format: "%02X", $0) }.joined()
            }
            if case .dict(let vd) = oldVRI {
                for key in vd.sortedKeys where key != newKey {
                    dss += " /" + PdfIncremental.escapeName(key) + " " + (try inc.serialize(vd[key]))
                }
            }
            if !newKey.isEmpty {
                dss += " /" + newKey + " <<"
                for (i, k) in ["Cert", "OCSP", "CRL"].enumerated() where !vri[i].isEmpty {
                    dss += " /\(k) [" + vri[i].joined(separator: " ") + "]"
                }
                dss += " >>"
            }
            dss += " >>"
        }
        dss += " >>"
        let (dssID, _) = inc.addObject(Array(dss.utf8))
        var cat = "<<\n  /Type /Catalog\n"
        cat += try inc.catalogCopy(skip: ["DSS"])
        cat += "  /DSS \(dssID) 0 R\n>>"
        let (catID, _) = inc.addObject(Array(cat.utf8))
        return try inc.finish(rootID: catID)
    }
}
