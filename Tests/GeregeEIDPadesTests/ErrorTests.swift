import Foundation
import XCTest
@testable import GeregeEIDPades

/// Error paths of prepare/complete (stable codes shared with the other SDKs).
final class ErrorTests: XCTestCase {
    private let g = GoldenTests()

    private func expect(_ code: EidPadesError.Code, _ body: () async throws -> Void, line: UInt = #line) async {
        do {
            try await body()
            XCTFail("expected \(code.rawValue)", line: line)
        } catch let e as EidPadesError {
            XCTAssertEqual(e.code, code, e.message, line: line)
        } catch {
            XCTFail("unexpected \(error)", line: line)
        }
    }

    private func prepared() throws -> (EidPades.Prepared, Data, GoldenTests.Manifest) {
        let m = try g.manifest()
        let c = try XCTUnwrap(m.cases.first { $0.name == "desktop-objstm-nopage" } ?? m.cases.first { $0.expect.signature != nil })
        let o = EidPades.PrepareOptions(signerCert: try g.certDER("citizen"),
                                        chain: [try g.certDER("04"), try g.certDER("03"), try g.certDER("02")],
                                        signingTime: m.signingTime, docId: c.prepare.docId)
        let p = try EidPades.prepare(pdf: Data(try g.file(c.input)), options: o)
        return (p, GoldenTests.unhex(try XCTUnwrap(c.expect.signature)), m)
    }

    func testPrepareRejectsInput() async throws {
        let m = try g.manifest()
        let o = EidPades.PrepareOptions(signerCert: try g.certDER("citizen"), signingTime: m.signingTime)
        await expect(.pdfInvalid) { _ = try EidPades.prepare(pdf: Data("not a pdf".utf8), options: o) }
        await expect(.pdfTooLarge) {
            _ = try EidPades.prepare(pdf: Data(repeating: 0x20, count: EidPades.maxInputBytes + 1), options: o)
        }
        var bad = o
        bad.signerCert = Data([0x30, 0x00])
        await expect(.signerInvalid) { _ = try EidPades.prepare(pdf: Data("%PDF-1.4".utf8), options: bad) }
        var badDoc = o
        badDoc.chain = [try g.certDER("04")]
        badDoc.docId = "NOT-A-UUID"
        await expect(.requestInvalid) { _ = try EidPades.prepare(pdf: Data(try g.file("input/quartz-pdf13.pdf")), options: badDoc) }
    }

    func testCompleteErrorCodes() async throws {
        let (p, sig, _) = try prepared()
        let root = try g.certDER("root")
        let offline = EidPades.CompleteOptions(tsaUrl: "http://127.0.0.1:9/", roots: [root])
        var tampered = sig
        tampered[tampered.count - 1] ^= 1
        await expect(.signatureInvalid) { _ = try await EidPades.complete(state: p.state, signature: tampered, options: offline) }
        await expect(.stateInvalid) { _ = try await EidPades.complete(state: Data("garbage".utf8), signature: sig, options: offline) }
        var st = p.state
        st[st.count - 1] ^= 1   // prepared PDF changed after prepare
        await expect(.stateInvalid) { _ = try await EidPades.complete(state: st, signature: sig, options: offline) }
        await expect(.tsaUnavailable) { _ = try await EidPades.complete(state: p.state, signature: sig, options: offline) }
    }

    /// APPEARANCE_SPEC.md §1, §3 (Go TestAppearanceRejects): placement/size invalid or text does not fit → REQUEST_INVALID.
    func testAppearanceRejects() async throws {
        let m = try g.manifest()
        let doc = Data(try g.file("input/quartz-pdf13.pdf")) // 612 × 792, 1 page
        let base = EidPades.PrepareOptions(signerCert: try g.certDER("citizen"),
                                           chain: [try g.certDER("04"), try g.certDER("03"), try g.certDER("02")],
                                           signingTime: m.signingTime, docId: "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d")
        typealias A = EidPades.SignatureAppearance
        let ok = A(x: 36, y: 36, width: 220, height: 64)
        func with(_ a: A, _ f: (inout EidPades.PrepareOptions) -> Void = { _ in }) -> EidPades.PrepareOptions {
            var o = base
            o.appearance = a
            f(&o)
            return o
        }
        let cases: [(String, EidPades.PrepareOptions)] = [
            ("page missing", with(A(page: 2, x: 36, y: 36, width: 220, height: 64))),
            ("negative page", with(A(page: -1, x: 36, y: 36, width: 220, height: 64))),
            ("off the page", with(A(x: 500, y: 36, width: 220, height: 64))),
            ("above the page", with(A(x: 36, y: 760, width: 220, height: 64))),
            ("low (QR < 1 pt)", with(A(x: 36, y: 36, width: 220, height: 44))),
            ("narrow (text)", with(A(x: 36, y: 36, width: 90, height: 64))),
            ("zero width", with(A(x: 36, y: 36, width: 0, height: 64))),
            ("NaN", with(A(x: .nan, y: 36, width: 220, height: 64))),
            ("> 14400", with(A(x: 36, y: 36, width: 220, height: 14401))),
            ("lang", with(A(x: 36, y: 36, width: 220, height: 64, lang: "de"))),
            ("/Name not written", with(ok) { $0.signerName = "a stream b" }),
            ("role control char", with(ok) { $0.claimedRole = "a\u{200E}b" }),
        ]
        for (name, o) in cases {
            do {
                _ = try EidPades.prepare(pdf: doc, options: o)
                XCTFail("\(name): expected REQUEST_INVALID")
            } catch let e as EidPadesError {
                XCTAssertEqual(e.code, .requestInvalid, "\(name): \(e.message)")
            }
        }
        // The minimum (45 pt high) is accepted and differs from the invisible signature.
        let p45 = try EidPades.prepare(pdf: doc, options: with(A(x: 36, y: 36, width: 220, height: 45)))
        XCTAssertNotEqual(p45.dtbs, try EidPades.prepare(pdf: doc, options: base).dtbs)
    }

    func testAppearanceNum100() throws {
        for (v, want) in [0: "0", 100: "1", 150: "1.5", 105: "1.05", 59528: "595.28", -50: "-0.5", -1234: "-12.34", 7: "0.07"] {
            XCTAssertEqual(Appearance.num100(v), want)
        }
        XCTAssertEqual(Appearance.round100(595.275), 59528)
        XCTAssertEqual(Appearance.round100(-0.005), 0)
        // Go TestVisibleRect: CropBox origin (10, 20), 602 × 792 pt, display (36, 36) 220 × 64 pt.
        let box = [1000, 2000, 61200, 81200]
        let want: [Int: [Int]] = [0: [4600, 5600, 26600, 12000], 90: [51200, 5600, 57600, 27600],
                                  180: [35600, 71200, 57600, 77600], 270: [4600, 55600, 11000, 77600]]
        for (rot, r) in want {
            XCTAssertEqual(try Appearance.rect(box: box, rot: rot, x: 3600, y: 3600, w: 22000, h: 6400), r, "rot \(rot)")
        }
        XCTAssertThrowsError(try Appearance.rect(box: box, rot: 90, x: 3600, y: 3600, w: 80000, h: 6400))
    }

    func testCleanFileName() {
        XCTAssertEqual(EidPades.cleanFileName("  Гэрээ\u{200B} №1.pdf \n"), "Гэрээ №1.pdf")
        XCTAssertNil(EidPades.cleanFileName("   "))
        XCTAssertNil(EidPades.cleanFileName(String(repeating: "а", count: 121)))
    }
}
