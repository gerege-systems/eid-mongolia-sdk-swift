import Foundation

// Minimal ASN.1 DER reader/writer (X.690) — only what the PAdES signing path needs: certificates, CRLs, OCSP,
// RFC 3161 and CMS. Writer output is byte-identical to Go's golang.org/x/crypto/cryptobyte / encoding/asn1 for the
// structures built here (definite lengths, minimal INTEGER encoding).

struct DERError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// One TLV. `raw` = the whole element, `value` = its contents (slices of the same buffer).
struct DER {
    let tag: UInt8
    let raw: ArraySlice<UInt8>
    let value: ArraySlice<UInt8>

    var isConstructed: Bool { tag & 0x20 != 0 }

    /// Parses exactly one element at the start of `b`.
    static func parse(_ b: ArraySlice<UInt8>) throws -> DER {
        var i = b.startIndex
        guard i < b.endIndex else { throw DERError("truncated") }
        let tag = b[i]
        guard tag & 0x1F != 0x1F else { throw DERError("high tag numbers not supported") }
        i += 1
        guard i < b.endIndex else { throw DERError("truncated length") }
        var len = Int(b[i])
        i += 1
        if len & 0x80 != 0 {
            let n = len & 0x7F
            guard n >= 1, n <= 4, i + n <= b.endIndex else { throw DERError("bad length") }
            len = 0
            for _ in 0..<n { len = len << 8 | Int(b[i]); i += 1 }
        }
        guard len >= 0, i + len <= b.endIndex else { throw DERError("length past end") }
        return DER(tag: tag, raw: b[b.startIndex..<(i + len)], value: b[i..<(i + len)])
    }

    static func parse(_ b: [UInt8]) throws -> DER { try parse(b[...]) }

    /// Children of a constructed element.
    func children() throws -> [DER] {
        var out: [DER] = []
        var rest = value
        while !rest.isEmpty {
            let e = try DER.parse(rest)
            out.append(e)
            rest = rest[e.raw.endIndex...]
        }
        return out
    }

    func child(_ i: Int) throws -> DER {
        let c = try children()
        guard i < c.count else { throw DERError("missing element \(i)") }
        return c[i]
    }

    func expect(_ t: UInt8) throws -> DER {
        guard tag == t else { throw DERError(String(format: "tag %02x, want %02x", tag, t)) }
        return self
    }

    var bytes: [UInt8] { Array(raw) }
    var contents: [UInt8] { Array(value) }

    /// OID in dotted form.
    var oid: String? {
        guard tag == 0x06, !value.isEmpty else { return nil }
        var parts: [UInt64] = []
        var v: UInt64 = 0
        for c in value {
            v = v << 7 | UInt64(c & 0x7F)
            if c & 0x80 == 0 { parts.append(v); v = 0 }
        }
        guard let first = parts.first else { return nil }
        let a = min(first / 40, 2), b = first - a * 40
        return ([a, b] + parts.dropFirst()).map(String.init).joined(separator: ".")
    }

    /// INTEGER contents as an unsigned magnitude (leading 0x00 removed).
    var unsignedInteger: [UInt8] {
        var v = Array(value)
        while v.count > 1, v[0] == 0 { v.removeFirst() }
        return v
    }

    /// UTCTime / GeneralizedTime.
    var time: Date? {
        let s = String(decoding: value, as: UTF8.self)
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        switch tag {
        case 0x17:
            f.dateFormat = "yyMMddHHmmss'Z'"
            // X.509: YY >= 50 → 19YY.
            f.twoDigitStartDate = DateComponents(calendar: Calendar(identifier: .gregorian),
                                                 timeZone: TimeZone(identifier: "UTC"), year: 1950).date
            return f.date(from: s)
        case 0x18:
            if s.contains(".") {
                // Fractional seconds: yyyyMMddHHmmss.fffZ
                let parts = s.dropLast().split(separator: ".")
                guard parts.count == 2 else { return nil }
                f.dateFormat = "yyyyMMddHHmmss"
                guard let base = f.date(from: String(parts[0])), let frac = Double("0." + parts[1]) else { return nil }
                return base.addingTimeInterval(frac)
            }
            f.dateFormat = "yyyyMMddHHmmss'Z'"
            return f.date(from: s)
        default:
            return nil
        }
    }

    /// String types (UTF8String, PrintableString, IA5String, …) as Swift String.
    var string: String? {
        switch tag {
        case 0x0C, 0x13, 0x16, 0x14, 0x1A: return String(decoding: value, as: UTF8.self)
        case 0x1E: // BMPString
            var u: [UInt16] = []
            var i = value.startIndex
            while i + 1 < value.endIndex { u.append(UInt16(value[i]) << 8 | UInt16(value[i + 1])); i += 2 }
            return String(decoding: u, as: UTF16.self)
        default: return nil
        }
    }
}

/// DER builder.
enum DERW {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [tag]
        let n = content.count
        if n < 0x80 {
            out.append(UInt8(n))
        } else {
            var lenBytes: [UInt8] = []
            var v = n
            while v > 0 { lenBytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
            out.append(0x80 | UInt8(lenBytes.count))
            out += lenBytes
        }
        return out + content
    }

    static func seq(_ parts: [UInt8]...) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    static func seq(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x30, parts.flatMap { $0 }) }
    static func set(_ parts: [[UInt8]]) -> [UInt8] { tlv(0x31, parts.flatMap { $0 }) }
    static func octet(_ b: [UInt8]) -> [UInt8] { tlv(0x04, b) }
    static let null: [UInt8] = [0x05, 0x00]
    static func bool(_ v: Bool) -> [UInt8] { [0x01, 0x01, v ? 0xFF : 0x00] }
    static func utf8(_ s: String) -> [UInt8] { tlv(0x0C, Array(s.utf8)) }

    /// INTEGER from an unsigned big-endian magnitude (minimal; 0x00 prefix when the high bit is set).
    static func uint(_ magnitude: [UInt8]) -> [UInt8] {
        var m = Array(magnitude.drop(while: { $0 == 0 }))
        if m.isEmpty { m = [0] }
        if m[0] & 0x80 != 0 { m.insert(0, at: 0) }
        return tlv(0x02, m)
    }

    static func int(_ v: Int) -> [UInt8] {
        precondition(v >= 0)
        var m: [UInt8] = []
        var x = v
        repeat { m.insert(UInt8(x & 0xFF), at: 0); x >>= 8 } while x > 0
        return uint(m)
    }

    /// OBJECT IDENTIFIER from dotted form.
    static func oid(_ dotted: String) -> [UInt8] {
        let p = dotted.split(separator: ".").compactMap { UInt64($0) }
        precondition(p.count >= 2)
        var body: [UInt8] = []
        for (i, v) in ([p[0] * 40 + p[1]] + p.dropFirst(2)).enumerated() {
            _ = i
            var chunk: [UInt8] = [UInt8(v & 0x7F)]
            var x = v >> 7
            while x > 0 { chunk.insert(UInt8(x & 0x7F) | 0x80, at: 0); x >>= 7 }
            body += chunk
        }
        return tlv(0x06, body)
    }

    static func algID(_ dotted: String, nullParams: Bool) -> [UInt8] {
        nullParams ? seq(oid(dotted), null) : seq(oid(dotted))
    }

    /// DER SET OF: elements sorted by their encoding (X.690 §11.6; Go `bytes.Compare`).
    static func sortedSet(_ elems: [[UInt8]]) -> [UInt8] {
        set(elems.sorted { $0.lexicographicallyPrecedes($1) })
    }
}

enum OID {
    static let data = "1.2.840.113549.1.7.1"
    static let signedData = "1.2.840.113549.1.7.2"
    static let contentType = "1.2.840.113549.1.9.3"
    static let messageDigest = "1.2.840.113549.1.9.4"
    static let signingCertV2 = "1.2.840.113549.1.9.16.2.47"
    static let timeStampToken = "1.2.840.113549.1.9.16.2.14"
    static let tstInfo = "1.2.840.113549.1.9.16.1.4"
    static let sha1 = "1.3.14.3.2.26"
    static let sha256 = "2.16.840.1.101.3.4.2.1"
    static let sha384 = "2.16.840.1.101.3.4.2.2"
    static let sha512 = "2.16.840.1.101.3.4.2.3"
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let sha256WithRSA = "1.2.840.113549.1.1.11"
    static let sha384WithRSA = "1.2.840.113549.1.1.12"
    static let sha512WithRSA = "1.2.840.113549.1.1.13"
    static let ecPublicKey = "1.2.840.10045.2.1"
    static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
    static let ecdsaWithSHA384 = "1.2.840.10045.4.3.3"
    static let ecdsaWithSHA512 = "1.2.840.10045.4.3.4"
    static let signerAttrV2 = "0.4.0.19122.1.1"
    static let role = "2.5.4.72"
    static let commonName = "2.5.4.3"
    static let givenName = "2.5.4.42"
    static let surname = "2.5.4.4"
    static let extKeyUsage = "2.5.29.37"
    static let crlDistributionPoints = "2.5.29.31"
    static let authorityInfoAccess = "1.3.6.1.5.5.7.1.1"
    static let ocspAccess = "1.3.6.1.5.5.7.48.1"
    static let kpTimeStamping = "1.3.6.1.5.5.7.3.8"
    static let kpOCSPSigning = "1.3.6.1.5.5.7.3.9"
    static let ocspBasic = "1.3.6.1.5.5.7.48.1.1"
}
