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

    func testCleanFileName() {
        XCTAssertEqual(EidPades.cleanFileName("  Гэрээ\u{200B} №1.pdf \n"), "Гэрээ №1.pdf")
        XCTAssertNil(EidPades.cleanFileName("   "))
        XCTAssertNil(EidPades.cleanFileName(String(repeating: "а", count: 121)))
    }
}
