// Conformance: the Go reference golden vectors (golden/, vendored by scripts/sync-pades-golden.sh) through the
// native Swift prepare/complete — dtbs, digest, prepared PDF, CMS and the FULL output bytes (sha256) must match.
// complete runs offline: HTTP from golden/http (key "METHOD URL sha256(body)[:8]"), clock = manifest.now,
// TSA nonce = Go seededReader (SHA-256 chain over "golden-nonce:<case>"), citizen signature = expect.signature.
import CryptoKit
import Foundation
import XCTest
@testable import GeregeEIDPades

final class GoldenTests: XCTestCase {
    struct Manifest: Decodable {
        var profile: String
        var signingTime: Date
        var now: Date
        var http: [String: String]
        var cases: [Case]
    }

    struct Case: Decodable {
        struct Appearance: Decodable {
            var page: Int?
            var x: Double
            var y: Double
            var width: Double
            var height: Double
            var lang: String?
            var exact: Bool?
        }
        struct Prep: Decodable {
            var appearance: Appearance?
            var docId: String?
            var verifyPage: Bool?
            var fileName: String?
            var lang: String?
            var reason: String?
            var claimedRole: String?
        }
        struct Expect: Decodable {
            var error: String?
            var signature: String?
            var signedAttrs: String?
            var inputSha256: String?
            var docId: String?
            var digest: String?
            var dtbs: String?
            var preparedSha256: String?
            var byteRange: [Int]?
            var outSha256: String?
            var revIndex: Int?
            var hasPage: Bool?
            var pageSha256: String?
            var cmsSha256: String?
            var sigRevSha256: String?
            var priorCmsSha256: [String]?
            var placement: Placement?
            /// PLACEMENT_SPEC.md §6b (golden v7): `suggestPlacement(input, appearance)` on every visible case.
            var suggestion: Suggestion?
            var suggestionError: String?
        }
        /// Go `pades.Suggestion`.
        struct Suggestion: Decodable {
            struct Size: Decodable { var width, height: Double }
            var page: Int
            var x, y, width, height: Double
            var status: String
            var pageWidth, pageHeight: Double
            var pageCount: Int
            var pages: [Size]
        }
        /// Go `pades.Placement` (PLACEMENT_SPEC.md) — every visible case has one.
        struct Placement: Decodable {
            var page: Int
            var x, y, width, height: Double
            var status: String
        }
        var name: String
        var input: String
        var prepare: Prep
        var expect: Expect
    }

    static let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("golden")

    func file(_ rel: String) throws -> [UInt8] { [UInt8](try Data(contentsOf: Self.dir.appendingPathComponent(rel))) }

    func certDER(_ name: String) throws -> Data {
        let pem = String(decoding: try file("pki/\(name).pem"), as: UTF8.self)
        guard let r = pem.range(of: "-----BEGIN CERTIFICATE-----"), let e = pem.range(of: "-----END CERTIFICATE-----"),
              let d = Data(base64Encoded: pem[r.upperBound..<e.lowerBound].split(whereSeparator: \.isNewline).joined()) else {
            throw XCTSkip("pki/\(name).pem")
        }
        return d
    }

    func manifest() throws -> Manifest {
        guard FileManager.default.fileExists(atPath: Self.dir.appendingPathComponent("manifest.json").path) else {
            throw XCTSkip("golden/ not vendored — scripts/sync-pades-golden.sh <ref>")
        }
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return try d.decode(Manifest.self, from: Data(try file("manifest.json")))
    }

    /// Replays golden/http.
    struct Replay: EidPadesTransport {
        let m: [String: String]
        let dir: URL
        func send(method: String, url: URL, contentType: String?, body: Data?) async throws -> Data {
            let h = Array(SHA256.hash(data: body ?? Data())).prefix(8).map { String(format: "%02x", $0) }.joined()
            let key = "\(method) \(url.absoluteString) \(h)"
            guard let f = m[key] else { throw DERError("no fixture for \(key)") }
            return try Data(contentsOf: dir.appendingPathComponent(f))
        }
    }

    /// Go golden_test seededReader: the first 8 bytes of SHA-256(seed ‖ 0x00).
    static func nonce(_ caseName: String) -> [UInt8] {
        Array(Array(SHA256.hash(data: Array("golden-nonce:\(caseName)".utf8) + [0])).prefix(8))
    }

    static func unhex(_ s: String) -> Data {
        var out = Data()
        var it = s.makeIterator()
        while let a = it.next(), let b = it.next() { out.append(UInt8(String([a, b]), radix: 16)!) }
        return out
    }

    func testVersion() throws {
        XCTAssertEqual(EidPades.version, try manifest().profile)
    }

    func testGoldenVectors() async throws {
        let m = try manifest()
        let chain = [try certDER("04"), try certDER("03"), try certDER("02")]
        let root = try certDER("root")
        let citizen = try certDER("citizen")
        var outputs: [String: Data] = [:]
        var full = 0, skipped: [String] = []
        for c in m.cases {
            let input: Data
            if c.input.hasPrefix("case:") {
                guard let prev = outputs[String(c.input.dropFirst(5))] else { skipped.append(c.name); continue }
                input = prev
            } else {
                input = Data(try file(c.input))
            }
            if let want = c.expect.inputSha256 { XCTAssertEqual(Crypto.hex(Crypto.sha256([UInt8](input))), want, c.name) }
            let o = EidPades.PrepareOptions(
                signerCert: citizen, chain: chain, reason: c.prepare.reason, claimedRole: c.prepare.claimedRole,
                signingTime: m.signingTime, docId: c.prepare.docId, verifyPage: c.prepare.verifyPage ?? false,
                fileName: c.prepare.fileName, lang: c.prepare.lang,
                appearance: c.prepare.appearance.map {
                    EidPades.SignatureAppearance(page: $0.page ?? 0, x: $0.x, y: $0.y, width: $0.width, height: $0.height,
                                                 lang: $0.lang, exact: $0.exact ?? false)
                })
            // suggestPlacement (PLACEMENT_SPEC §6b) field-for-field, before prepare (Go golden_test order).
            var suggestion: EidPades.PlacementSuggestion?
            if let a = o.appearance {
                do {
                    let s = try EidPades.suggestPlacement(pdf: input, appearance: a)
                    suggestion = s
                    XCTAssertNil(c.expect.suggestionError, "\(c.name): suggestPlacement succeeded, Go failed")
                    if let want = c.expect.suggestion {
                        XCTAssertEqual(s.page, want.page, "\(c.name) suggestion page")
                        XCTAssertEqual([s.x, s.y, s.width, s.height, s.pageWidth, s.pageHeight],
                                       [want.x, want.y, want.width, want.height, want.pageWidth, want.pageHeight], "\(c.name) suggestion")
                        XCTAssertEqual(s.status.rawValue, want.status, "\(c.name) suggestion status")
                        XCTAssertEqual(s.pageCount, want.pageCount, "\(c.name) suggestion pageCount")
                        XCTAssertEqual(s.pages.map { [$0.width, $0.height] }, want.pages.map { [$0.width, $0.height] }, "\(c.name) suggestion pages")
                    } else {
                        XCTFail("\(c.name): visible case without expect.suggestion")
                    }
                } catch let e as EidPadesError {
                    XCTAssertEqual(e.code.rawValue, c.expect.suggestionError, "\(c.name) suggestPlacement: \(e.message)")
                }
            }
            let p: EidPades.Prepared
            do {
                p = try EidPades.prepare(pdf: input, options: o)
            } catch let e as EidPadesError {
                XCTAssertEqual(e.code.rawValue, c.expect.error, "\(c.name): \(e.message)")
                continue
            }
            XCTAssertNil(c.expect.error, "\(c.name): prepare succeeded, Go failed with \(c.expect.error ?? "")")
            XCTAssertEqual(Crypto.hex([UInt8](p.digest)), c.expect.digest, "\(c.name) digest")
            XCTAssertEqual(Crypto.hex([UInt8](p.dtbs)), c.expect.dtbs, "\(c.name) dtbs")
            XCTAssertEqual(p.docId, c.expect.docId ?? "", "\(c.name) docId")
            let st = try State.decode([UInt8](p.state))
            if let want = c.expect.signedAttrs { XCTAssertEqual(Crypto.hex(st.signedAttrs), want, "\(c.name) signedAttrs") }
            XCTAssertEqual(st.preparedSha256, c.expect.preparedSha256, "\(c.name) prepared PDF")
            XCTAssertEqual(st.byteRange, c.expect.byteRange, "\(c.name) byteRange")
            XCTAssertEqual(p.placement.map { [Double($0.page), $0.x, $0.y, $0.width, $0.height] },
                           c.expect.placement.map { [Double($0.page), $0.x, $0.y, $0.width, $0.height] }, "\(c.name) placement")
            XCTAssertEqual(p.placement?.status.rawValue, c.expect.placement?.status, "\(c.name) placement status")
            // suggestion ⊇ placement, except page0-two-verify (unsigned input: suggestPlacement has no docId, §6b).
            if let s = suggestion, c.name != "page0-two-verify" {
                XCTAssertEqual(p.placement, EidPades.Placement(page: s.page, x: s.x, y: s.y, width: s.width, height: s.height,
                                                               status: s.status), "\(c.name) suggestion ≠ placement")
            }
            if o.appearance != nil { XCTAssertNotNil(suggestion, "\(c.name): prepare ok, suggestPlacement failed") }
            guard let sigHex = c.expect.signature else { throw XCTSkip("manifest without expect.signature") }

            var co = EidPades.CompleteOptions(tsaUrl: "http://tsa.pki.test/", roots: [root],
                                              transport: Replay(m: m.http, dir: Self.dir))
            let now = m.now
            co.now = { now }
            co.sleep = { _ in }
            let n = Self.nonce(c.name)
            co.nonce = { n }
            do {
                let done = try await EidPades.complete(state: p.state, signature: Self.unhex(sigHex), options: co)
                XCTAssertNil(c.expect.error, c.name)
                XCTAssertEqual(Crypto.hex(Crypto.sha256([UInt8](done.cms))), c.expect.cmsSha256, "\(c.name) CMS")
                XCTAssertEqual(done.outSha256, c.expect.outSha256, "\(c.name) output")
                XCTAssertEqual(Crypto.hex(Crypto.sha256([UInt8](done.pdf))), done.outSha256)
                XCTAssertEqual(done.hasPage, c.expect.hasPage ?? false, c.name)
                XCTAssertEqual(done.pageSha256, c.expect.pageSha256, c.name)
                XCTAssertEqual(done.docId, c.expect.docId ?? "", c.name)
                XCTAssertEqual(st.revIndex, c.expect.revIndex, c.name)
                XCTAssertEqual(done.revIndex, c.expect.revIndex, c.name)
                XCTAssertEqual(done.sigRevSha256, c.expect.sigRevSha256, "\(c.name) sigRev")
                XCTAssertEqual(done.priorCmsSha256, c.expect.priorCmsSha256 ?? [], "\(c.name) priorCms")
                // Prior signatures' revisions = each earlier case's own sigRevSha256 (CA mode A `sig_rev_sha256`), in
                // document order along the `case:` chain (golden v5 `quartz-pdf13-visible-third` has two).
                func revisions(_ input: String) -> [String] {
                    guard input.hasPrefix("case:"), let prev = m.cases.first(where: { $0.name == String(input.dropFirst(5)) }) else { return [] }
                    return revisions(prev.input) + [prev.expect.sigRevSha256 ?? ""]
                }
                XCTAssertEqual(done.priorRevisionSha256, revisions(c.input), "\(c.name) priorRevision")
                XCTAssertEqual(done.signerCert, citizen, c.name)
                try checkRegistration(done, c)
                outputs[c.name] = done.pdf
                full += 1
            } catch let e as EidPadesError {
                XCTAssertEqual(e.code.rawValue, c.expect.error, "\(c.name): \(e.message)")
            }
        }
        print("golden: \(full) full prepare+complete byte-identical (visible: \(m.cases.filter { $0.prepare.appearance != nil }.count)); skipped: \(skipped)")
        XCTAssertGreaterThanOrEqual(m.cases.filter { $0.prepare.appearance != nil }.count, 11)
        XCTAssertEqual(m.cases.filter { $0.prepare.appearance != nil && $0.expect.error == nil }.count,
                       m.cases.filter { $0.expect.placement != nil }.count)
        XCTAssertEqual(m.cases.filter { $0.prepare.appearance != nil }.count,
                       m.cases.filter { $0.expect.suggestion != nil || $0.expect.suggestionError != nil }.count)
        XCTAssertGreaterThanOrEqual(m.cases.filter { $0.prepare.appearance?.exact == true }.count, 5)
        XCTAssertEqual(full, m.cases.filter { $0.expect.error == nil }.count, "every non-error case must complete byte-identically")
        XCTAssertTrue(skipped.isEmpty)
    }

    /// `Completed.registration` = Go `pades.Registration`: fileName from prepare, pageSha256 only for revIndex 1, prior
    /// signatures only as priorCmsSha256 (never also as priorRevisionSha256 — the CA answers 400), signerEtsi.
    func checkRegistration(_ done: EidPades.Completed, _ c: Case) throws {
        XCTAssertEqual(done.fileName, c.prepare.fileName.flatMap(EidPades.cleanFileName), c.name)
        guard done.fileName != nil, done.revIndex > 1 || done.hasPage else {
            XCTAssertThrowsError(try done.registration(medium: .token), c.name)
            return
        }
        let sid = "00000000-0000-4000-8000-000000000001"
        let obo = done.claimedRole == nil ? nil : "NTRMN-1234567"
        XCTAssertEqual(done.claimedRole, c.prepare.claimedRole?.nilIfEmptyForTest, c.name)
        // medium inferred from sessionId (CA pairing); inconsistent pairs fail fast.
        XCTAssertEqual(try done.registration(onBehalfOf: obo).medium, .token, c.name)
        XCTAssertEqual(try done.registration(sessionId: sid, onBehalfOf: obo).medium, .phone, c.name)
        XCTAssertThrowsError(try done.registration(medium: .phone, onBehalfOf: obo), c.name)
        XCTAssertThrowsError(try done.registration(medium: .token, sessionId: sid, onBehalfOf: obo), c.name)
        if done.claimedRole != nil {
            XCTAssertThrowsError(try done.registration(sessionId: sid), c.name) { e in
                XCTAssertEqual((e as? EidPadesError)?.code, .requestInvalid)
            }
        }
        let r = try done.registration(medium: .phone, sessionId: sid, onBehalfOf: obo)
        XCTAssertEqual(r.docID, done.docId, c.name)
        XCTAssertEqual(r.revIndex, done.revIndex, c.name)
        XCTAssertEqual(r.fileName, done.fileName, c.name)
        XCTAssertEqual(r.cms, done.cms.base64EncodedString(), c.name)
        XCTAssertEqual(r.pageSha256, done.revIndex == 1 ? done.pageSha256 : nil, c.name)
        XCTAssertEqual(r.priorCmsSha256, done.priorCmsSha256.isEmpty ? nil : done.priorCmsSha256, c.name)
        XCTAssertNil(r.priorRevisionSha256, c.name)
        XCTAssertEqual(r.priorSignatures.map(\.revisionSha256), done.priorRevisionSha256, c.name)
        XCTAssertEqual(r.signerEtsi, "PNOMN-00000000000", c.name)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(r)) as? [String: Any])
        XCTAssertEqual(Set(json.keys), Set(["docID", "revIndex", "medium", "sessionID", "cms", "fileName", "inSha256",
                                            "sigRevSha256", "outSha256", "signerEtsi"]
                                           + (done.revIndex == 1 ? ["pageSha256"] : ["priorCmsSha256"])
                                           + (obo == nil ? [] : ["onBehalfOf"])), c.name)
        XCTAssertEqual(json["medium"] as? String, "phone")
    }
}

private extension String {
    var nilIfEmptyForTest: String? { isEmpty ? nil : self }
}
