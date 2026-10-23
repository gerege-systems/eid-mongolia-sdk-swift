// APPEARANCE_SPEC.md §6.1 image input checks (REQUEST_INVALID before the PDF is parsed, suggestPlacement too), the
// default sizes (§6.3) and the registration images (§6.6) — Go TestAppearanceImageInput. The images are golden v10's
// (manifest `prepare.appearance`), so no zlib encoder is needed here.
import Foundation
import XCTest
@testable import GeregeEIDPades

final class ImageInputTests: XCTestCase {
    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("golden")

    struct Manifest: Decodable {
        struct Case: Decodable {
            struct Prep: Decodable { var appearance: GoldenTests.Case.Appearance? }
            var name: String
            var prepare: Prep
        }
        var cases: [Case]
    }

    func images() throws -> (sig: EidPades.PdfImage, stamp: EidPades.PdfImage, badAlpha: EidPades.PdfImage) {
        let m = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: Self.dir.appendingPathComponent("manifest.json")))
        func app(_ n: String) throws -> GoldenTests.Case.Appearance {
            try XCTUnwrap(m.cases.first { $0.name == n }?.prepare.appearance, n)
        }
        return (try XCTUnwrap(app("img-signature-stamp").signatureImage), try XCTUnwrap(app("img-signature-stamp").stampImage),
                try XCTUnwrap(app("img-bad-alpha").signatureImage))
    }

    func testImageInput() throws {
        let doc = try Data(contentsOf: Self.dir.appendingPathComponent("input/quartz-pdf13.pdf"))
        let (sig, stamp, badAlpha) = try images()
        func mod(_ f: (inout EidPades.PdfImage) -> Void) -> EidPades.PdfImage {
            var im = sig
            f(&im)
            return im
        }
        let bad: [String: EidPades.PdfImage] = [
            "sha256 upper case": mod { $0.sha256 = $0.sha256.uppercased() },
            "sha256 short": mod { $0.sha256 = String($0.sha256.dropLast()) },
            "colour 256": mod { $0.color[1] = 256 },
            "colour negative": mod { $0.color[0] = -1 },
            "colour 2 values": mod { $0.color = [1, 2] },
            "width 1601": mod { $0.width = 1601 },
            "height 0": mod { $0.height = 0 },
            "alpha empty": mod { $0.alpha = Data() },
            "alpha not zlib": mod { $0.alpha = Data("not zlib".utf8) },
            "alpha more bytes": mod { $0.height -= 1 },
            "alpha fewer bytes": badAlpha,
            "alpha trailing byte": mod { $0.alpha.append(0) },
            "alpha > 300 KiB": mod { $0.alpha = Data(count: 300 << 10 + 1) },
        ]
        for (name, im) in bad {
            XCTAssertThrowsError(try EidPades.suggestPlacement(pdf: doc, appearance: .init(x: 36, y: 36, signatureImage: im)), name) { e in
                XCTAssertEqual((e as? EidPadesError)?.code, .requestInvalid, name)
            }
        }
        let sizes: [(EidPades.SignatureAppearance, Double, Double)] = [
            (.init(x: 36, y: 36), 220, 64),
            (.init(x: 36, y: 36, signatureImage: sig), 220, 110),
            (.init(x: 36, y: 36, stampImage: stamp), 240, 147.5),
            (.init(x: 36, y: 36, signatureImage: sig, stampImage: stamp), 240, 147.5),
            (.init(x: 36, y: 36, width: 300, height: 180, stampImage: stamp), 300, 180),
        ]
        for (a, w, h) in sizes {
            let s = try EidPades.suggestPlacement(pdf: doc, appearance: a)
            XCTAssertEqual([s.width, s.height], [w, h])
        }

        let done = EidPades.Completed(
            pdf: Data(), cms: Data([1]), docId: "d", outSha256: "o", inSha256: "i", hasPage: false, pageSha256: nil,
            revIndex: 2, sigRevSha256: "s", priorCmsSha256: [], priorRevisionSha256: [], signerCert: Data(),
            fileName: "a.pdf", claimedRole: "x",
            images: [.init(kind: .signature, sha256: sig.sha256), .init(kind: .stamp, sha256: stamp.sha256)])
        let enc = JSONEncoder()
        enc.outputFormatting = .sortedKeys
        let j = String(decoding: try enc.encode(done.registration(onBehalfOf: "NTRMN-1234567")), as: UTF8.self)
        XCTAssertTrue(j.contains(#""images":[{"kind":"signature","sha256":"\#(sig.sha256)"},{"kind":"stamp","sha256":"\#(stamp.sha256)"}]"#), j)
        let plain = EidPades.Completed(
            pdf: Data(), cms: Data([1]), docId: "d", outSha256: "o", inSha256: "i", hasPage: false, pageSha256: nil,
            revIndex: 2, sigRevSha256: "s", priorCmsSha256: [], priorRevisionSha256: [], signerCert: Data(), fileName: "a.pdf")
        XCTAssertFalse(String(decoding: try enc.encode(plain.registration()), as: UTF8.self).contains(#""images""#))
    }

    /// APPEARANCE_SPEC §6.1: no preset dictionary — FDICT is rejected even with DICTID = 1 (Adler-32 of the empty
    /// dictionary), which Go `compress/zlib` would accept (Go v0.16.0 checks the bit explicitly).
    func testFDICT() throws {
        // zlib header 78 BB... craft: CMF 0x78, FLG with FDICT (0x20) and FCHECK so (CMF·256 + FLG) % 31 == 0.
        func stream(dictID: UInt32) -> [UInt8] {
            var flg: UInt8 = 0x20
            while (0x78 * 256 + Int(flg)) % 31 != 0 { flg += 1 }
            let id = [UInt8(dictID >> 24), UInt8(dictID >> 16 & 0xFF), UInt8(dictID >> 8 & 0xFF), UInt8(dictID & 0xFF)]
            // stored block, 1 byte 0x00; Adler-32 of [0] = 0x00010001.
            return [0x78, flg] + id + [0x01, 0x01, 0x00, 0xFE, 0xFF, 0x00] + [0x00, 0x01, 0x00, 0x01]
        }
        XCTAssertThrowsError(try Appearance.checkImage(.init(w: 1, h: 1, color: [0, 0, 0], alpha: stream(dictID: 1))))
        XCTAssertThrowsError(try Appearance.checkImage(.init(w: 1, h: 1, color: [0, 0, 0], alpha: stream(dictID: 2))))
    }
}
