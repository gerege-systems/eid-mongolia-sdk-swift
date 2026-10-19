// PLACEMENT_SPEC.md conformance: the occupancy scanner and candidate search against the Go reference vectors
// (golden/placement/vectors.json, box-for-box), plus robustness on malformed content / broken streams.
import Foundation
import XCTest
@testable import GeregeEIDPades

final class PlacementTests: XCTestCase {
    struct Vector: Decodable {
        struct Expect: Decodable {
            var box: [Int]
            var rotate: Int
            var boxes: [[Int]]?
            var x, y: Int
            var status: String
        }
        var name: String
        var input: String
        var page: Int
        var request: [Double]
        var expect: Expect
    }

    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("golden")

    /// Scanner + choice exactly as PadesSignature.prepare runs them.
    static func run(_ doc: [UInt8], page n: Int, request q: [Double]) throws
        -> (box: [Int], rot: Int, boxes: [[Int]]?, result: StampPlacement.Result) {
        let inc = try PdfIncremental(doc)
        guard let p = try Appearance.nthPage(inc.reader, inc.root["Pages"], n) else { throw PdfError("page \(n)") }
        let (box, rot) = try Appearance.geometry(inc.reader, p.dict)
        let x = Appearance.round100(q[0]), y = Appearance.round100(q[1])
        let w = Appearance.round100(q[2]), h = Appearance.round100(q[3])
        let boxes = try? Occupancy.scan(inc.reader, page: p.dict, pageID: p.ref.id, box: box)
        let res = StampPlacement.choose(inc.reader, page: p.dict, pageID: p.ref.id, box: box, rot: rot, x: x, y: y, w: w, h: h)
        return (box, rot, boxes, res)
    }

    func testVectors() throws {
        let url = Self.dir.appendingPathComponent("placement/vectors.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw XCTSkip("golden/placement not vendored — scripts/sync-pades-golden.sh <ref>")
        }
        let vs = try JSONDecoder().decode([Vector].self, from: Data(contentsOf: url))
        XCTAssertEqual(vs.count, 29)
        for v in vs {
            let doc = [UInt8](try Data(contentsOf: Self.dir.appendingPathComponent(v.input)))
            let got = try Self.run(doc, page: v.page, request: v.request)
            XCTAssertEqual(got.box, v.expect.box, "\(v.name) box")
            XCTAssertEqual(got.rot, v.expect.rotate, "\(v.name) rotate")
            XCTAssertEqual(got.boxes, v.expect.boxes, "\(v.name) boxes")
            XCTAssertEqual(got.result.status.rawValue, v.expect.status, "\(v.name) status")
            XCTAssertEqual([got.result.x, got.result.y], [v.expect.x, v.expect.y], "\(v.name) position")
        }
    }

    /// Go TestPlacementCandidates: the trial order on A4 with the portal's default request.
    func testCandidates() {
        let c = StampPlacement.candidates(vw: 59528, vh: 84189, x: 34000, y: 3600, w: 22000, h: 6400)
        XCTAssertTrue(c[0] == (34000, 3600) && c[1] == (3528, 3600) && c[2] == (34000, 4800))
        let n = (84189 - 3600 - 3600 - 6400) / 1200
        XCTAssertEqual(c.count, 2 + 2 * n)
        XCTAssertTrue(c[2 + n] == (3528, 4800))
        let centred = StampPlacement.candidates(vw: 1000, vh: 3000, x: 400, y: 0, w: 200, h: 100)
        XCTAssertEqual(centred.count, 3)
        XCTAssertTrue(centred[1] == (400, 1200))
    }

    // MARK: - Robustness

    /// Go placement_test fxPDF: a minimal classic-xref PDF, objs[0] = object 1 (Catalog).
    static func pdf(_ objs: [[UInt8]]) -> [UInt8] {
        var b = Array("%PDF-1.4\n%\u{e2}\u{e3}\u{cf}\u{d3}\n".utf8)
        var offs: [Int] = []
        for (i, o) in objs.enumerated() {
            offs.append(b.count)
            b += Array("\(i + 1) 0 obj\n".utf8) + o + Array("\nendobj\n".utf8)
        }
        let x = b.count
        b += Array("xref\n0 \(objs.count + 1)\n0000000000 65535 f \n".utf8)
        for o in offs { b += Array(String(format: "%010d 00000 n \n", o).utf8) }
        b += Array("trailer\n<< /Size \(objs.count + 1) /Root 1 0 R >>\nstartxref\n\(x)\n%%EOF\n".utf8)
        return b
    }

    static func stream(_ dict: String, _ data: [UInt8]) -> [UInt8] {
        Array("<< \(dict)/Length \(data.count) >>\nstream\n".utf8) + data + Array("\nendstream".utf8)
    }

    /// One letter page whose content is `content` (+ a self-recursive form /X, a Type1 /F1 with two widths).
    static func page(_ content: [UInt8], filter: String = "") -> [UInt8] {
        pdf([
            Array("<< /Type /Catalog /Pages 2 0 R >>".utf8),
            Array("<< /Type /Pages /Kids [3 0 R] /Count 1 >>".utf8),
            Array("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> /Contents 4 0 R >>".utf8),
            stream(filter, content),
            Array("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 32 /Widths [250 300] >>".utf8),
            stream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X 6 0 R >> >> ", content),
        ])
    }

    func status(_ doc: [UInt8]) throws -> StampPlacement.Status {
        try Self.run(doc, page: 1, request: [340, 36, 220, 64]).result.status
    }

    /// zlib framing (RFC 1950): header, truncation and Adler-32 errors make the page unscannable, never a crash.
    func testBrokenFlate() throws {
        // "0 g 340 36 220 64 re f" (fills the requested spot), zlib level 9 from Go compress/zlib.
        let ok = try Occupancy.inflate(Self.zlib, limit: 1 << 20)
        XCTAssertEqual(String(decoding: ok, as: UTF8.self), "0 g 340 36 220 64 re f")
        XCTAssertEqual(try status(Self.page(Self.zlib, filter: "/Filter /FlateDecode ")), .moved)
        var badAdler = Self.zlib
        badAdler[badAdler.count - 1] ^= 1
        var badHeader = Self.zlib
        badHeader[1] ^= 1                                      // FCHECK
        // FDICT (0x78 0x20, FCHECK valid): Go accepts DICTID 1 (Adler-32 of no dictionary), rejects any other.
        let dict1 = [0x78, 0x20, 0, 0, 0, 1] + Self.zlib.dropFirst(2)
        let dict2 = [0x78, 0x20, 0, 0, 0, 2] + Self.zlib.dropFirst(2)
        let truncated = Array(Self.zlib.dropLast(3))           // Adler-32 cut
        let truncatedData = Array(Self.zlib.dropLast(8))       // deflate data cut
        var trailing = Self.zlib
        trailing += [0x20, 0x41, 0x42]                         // bytes after the checksum are ignored
        for (name, data, want) in [("adler", badAdler, StampPlacement.Status.unscanned), ("header", badHeader, .unscanned),
                                   ("fdict-1", dict1, .moved), ("fdict-2", dict2, .unscanned),
                                   ("truncated", truncated, .unscanned), ("truncated-data", truncatedData, .unscanned),
                                   ("empty", [], .unscanned), ("trailing", trailing, .moved)] {
            XCTAssertEqual(try status(Self.page(data, filter: "/Filter /FlateDecode ")), want, name)
        }
        // Unsupported filter / parameters.
        XCTAssertEqual(try status(Self.page(Self.zlib, filter: "/Filter /FlateDecode /DecodeParms << /Predictor 12 >> ")), .unscanned)
        XCTAssertEqual(try status(Self.page(Self.zlib, filter: "/Filter [/FlateDecode] /DecodeParms [null] ")), .moved)
        XCTAssertEqual(try status(Self.page(Self.zlib, filter: "/Filter [/FlateDecode /FlateDecode] ")), .unscanned)
        // Output budget: a stream inflating past 4 MiB.
        XCTAssertThrowsError(try Occupancy.inflate(Self.zlib, limit: 10))
    }

    /// Go compress/zlib BestCompression of "0 g 340 36 220 64 re f".
    static let zlib: [UInt8] = [0x78, 0xda, 0x32, 0x50, 0x48, 0x57, 0x30, 0x36, 0x31, 0x50, 0x30, 0x36, 0x53, 0x30, 0x32, 0x32,
                                0x50, 0x30, 0x33, 0x51, 0x28, 0x4a, 0x55, 0x48, 0x03, 0x04, 0x00, 0x00, 0xff, 0xff, 0x31, 0xed, 0x04, 0xb3]

    /// Arbitrary content bytes (Go FuzzOccupancy): the scanner never traps, loops or escapes its limits; it either
    /// returns boxes or reports unscannable. Deterministic PRNG so failures reproduce.
    func testArbitraryContent() throws {
        var seed: UInt64 = 0x9E37_79B9_7F4A_7C15
        func next() -> UInt64 {
            seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17
            return seed
        }
        let alphabet = Array("0123456789.-+ \n\r\t()<>[]{}/%#\\qQcmwgGrRkKsSfFbBnWhlvyreTcTwTzTLTfTdTDTmTjTJ'\"*DoBIIDEIBTETshcsCS".utf8)
        let seeds: [[UInt8]] = [
            Array("BT /F1 12 Tf (abc) Tj ET q 1 0 0 1 0 0 cm 0 0 10 10 re f Q BI /W 1 ID x EI".utf8),
            Array("q 1e308 0 0 1e308 0 0 cm 1 w 0 0 m 99999999999999999999999999999 1 l S Q".utf8),
            Array("BT /F1 99999999999999999999999999999 Tf 99999999999999999999999999999 Tz (aaaa) Tj ET".utf8),
            Array("/X Do".utf8),
            Array(String(repeating: "[", count: 40).utf8),
            Array(String(repeating: "q ", count: 70).utf8),
            Array("BI /W 1 ID".utf8),
            Array("(unterminated \\".utf8),
            Array("<abc".utf8),
        ]
        var docs = seeds
        for _ in 0..<300 {
            let n = Int(next() % 400)
            docs.append((0..<n).map { _ in alphabet[Int(next() % UInt64(alphabet.count))] })
        }
        for _ in 0..<100 {
            let n = Int(next() % 300)
            docs.append((0..<n).map { _ in UInt8(truncatingIfNeeded: next()) })
        }
        for content in docs {
            let doc = Self.page(content)
            let got = try Self.run(doc, page: 1, request: [340, 36, 220, 64])
            if got.result.status == .unscanned { XCTAssertNil(got.boxes) } else { XCTAssertNotNil(got.boxes) }
        }
        // The self-recursive form hits the depth limit, never recursion without end.
        XCTAssertEqual(try status(Self.page(Array("/X Do".utf8))), .unscanned)
    }
}
