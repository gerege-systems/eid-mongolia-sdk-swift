// PLACEMENT_SPEC.md §6b: the checks suggestPlacement shares with prepare (Go TestSuggestPlacementErrors, Android
// SuggestPlacementTest). Field-for-field results are in GoldenTests (expect.suggestion).
import Foundation
import XCTest
@testable import GeregeEIDPades

final class SuggestPlacementTests: XCTestCase {
    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("golden")

    func file(_ p: String) throws -> Data { try Data(contentsOf: Self.dir.appendingPathComponent(p)) }

    func testErrors() throws {
        let table = try file("input/table-bottom.pdf"), enc = try file("input/encrypted.pdf")
        let a = EidPades.SignatureAppearance(x: 340, y: 36, width: 220, height: 64)
        let cases: [(String, Data, EidPades.SignatureAppearance, EidPadesError.Code)] = [
            ("not-pdf", Data("hello".utf8), a, .pdfInvalid),
            ("encrypted", enc, a, .pdfEncrypted),
            ("page-beyond", table, .init(page: 2, x: 340, y: 36, width: 220, height: 64), .requestInvalid),
            ("outside", table, .init(x: 400, y: 36, width: 220, height: 64, exact: true), .requestInvalid),
            ("outside-auto", table, .init(x: 400, y: 36, width: 220, height: 64), .requestInvalid),
            ("negative", table, .init(x: -1, y: 36, width: 220, height: 64), .requestInvalid),
            ("zero-size", table, .init(x: 1, y: 36, width: 0, height: 64), .requestInvalid),
        ]
        for (name, doc, app, code) in cases {
            XCTAssertThrowsError(try EidPades.suggestPlacement(pdf: doc, appearance: app), name) { e in
                XCTAssertEqual((e as? EidPadesError)?.code, code, name)
            }
        }
        let s = try EidPades.suggestPlacement(pdf: table, appearance: .init(x: 340, y: 36, width: 220, height: 64, exact: true))
        XCTAssertEqual(s.status, .overlap)
        XCTAssertEqual([s.x, s.y], [340, 36])
        XCTAssertEqual(s.pageCount, 1)
        XCTAssertEqual(s.pages.count, 1)
        // Without exact the same request moves off the table (golden table-bottom-visible).
        let m = try EidPades.suggestPlacement(pdf: table, appearance: a)
        XCTAssertEqual(m.status, .moved)
    }
}
