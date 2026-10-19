// PLACEMENT_SPEC.md §1a: appearance.page 0 = the last page that is not an eID verify page (Go TestDefaultStampPage).
import Foundation
import XCTest
@testable import GeregeEIDPades

final class DefaultStampPageTests: XCTestCase {
    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("golden")
    static let docA = "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182"

    func file(_ p: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: Self.dir.appendingPathComponent(p))) }

    func check(_ doc: [UInt8], _ docID: String, _ page: Int, _ n: Int, _ name: String) throws {
        let got = try Appearance.defaultStampPage(doc, verifyURI: Prechecks.verifyURLPrefix + docID)
        XCTAssertEqual([got.page, got.n], [page, n], name)
    }

    func testDefaultStampPage() throws {
        try check(file("input/two-verify.pdf"), Self.docA, 1, 3, "two verify pages")
        try check(file("input/two-verify.pdf"), "a6b7c8d9-e0f1-4a2b-9c3d-4e5f60718293", 3, 3, "other docId")
        try check(file("input/fake-verify.pdf"), Self.docA, 2, 2, "fake verify")
        try check(file("input/quartz-pdf13.pdf"), Self.docA, 1, 1, "no verify page")
    }

    /// Hand-built pages: a direct /Link annotation, every page a verify page → the last page.
    func testAllVerifyPages() throws {
        let uri = Prechecks.verifyURLPrefix + Self.docA
        var b = "%PDF-1.4\n"
        var offs: [Int] = []
        let objs = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [<< /Subtype /Link /A << /S /URI /URI (\(uri)) >> >>] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI (\(uri)) >> >>",
        ]
        for (i, o) in objs.enumerated() {
            offs.append(b.utf8.count)
            b += "\(i + 1) 0 obj\n\(o)\nendobj\n"
        }
        let x = b.utf8.count
        b += "xref\n0 \(objs.count + 1)\n0000000000 65535 f \n"
        for o in offs { b += String(format: "%010d 00000 n \n", o) }
        b += "trailer\n<< /Size \(objs.count + 1) /Root 1 0 R >>\nstartxref\n\(x)\n%%EOF\n"
        try check(Array(b.utf8), Self.docA, 2, 2, "all verify")
    }
}
