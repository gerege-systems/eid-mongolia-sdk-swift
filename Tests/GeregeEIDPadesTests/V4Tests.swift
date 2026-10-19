// Golden v4 (Go reference v0.8.0): revocation-evidence matching/freshness and revoked = hard error in `complete`'s
// OCSP/CRL collection (golden/validate/dss-*.pdf — the citizen's OCSP/CRL replaced in the DSS), PRECHECKS #2a/#2b
// structure checks (golden/validate/deep-nesting*.pdf, Go TestCheckStructureObjStmGraph inputs) and #4 direct /Encrypt.
import CryptoKit
import Foundation
import XCTest
@testable import GeregeEIDPades

final class V4Tests: XCTestCase {
    private let g = GoldenTests()

    // MARK: - PRECHECKS #2a / #2b / #4

    func testDeepNestingRejected() throws {
        let m = try g.manifest()
        let o = EidPades.PrepareOptions(signerCert: try g.certDER("citizen"),
                                        chain: [try g.certDER("04"), try g.certDER("03"), try g.certDER("02")],
                                        signingTime: m.signingTime, verifyPage: true, fileName: "x.pdf")
        for name in ["deep-nesting", "deep-nesting-objstm"] {
            let doc = try g.file("validate/\(name).pdf")
            XCTAssertThrowsError(try Structure.check(doc), name)
            XCTAssertThrowsError(try EidPades.prepare(pdf: Data(doc), options: o), name) {
                XCTAssertEqual(($0 as? EidPadesError)?.code, .pdfInvalid, name)
            }
        }
        // Every golden input passes the structure check.
        for c in m.cases where !c.input.hasPrefix("case:") {
            XCTAssertNoThrow(try Structure.check(try g.file(c.input)), c.input)
        }
        // 256 levels pass, 257 do not.
        func nested(_ n: Int) -> [UInt8] {
            Array(("%PDF-1.4\n1 0 obj\n<< /X " + String(repeating: "[", count: n - 1) + String(repeating: "]", count: n - 1)
                   + " >>\nendobj\n").utf8)
        }
        XCTAssertNoThrow(try Structure.check(nested(256)))
        XCTAssertThrowsError(try Structure.check(nested(257)))
    }

    /// Go `xrefStreamPDF`: obj 1 Catalog (/X 3 0 R), obj 2 xref stream (/Size size, W [1 2 1]), obj 3 = object 0 of
    /// ObjStm 4 (row3 replaces its row), obj 4 ObjStm (/Length length4; row4 replaces its row).
    private func xrefStreamPDF(_ size: String, _ length4: String, row3: [UInt8]? = nil, row4: [UInt8]? = nil) -> [UInt8] {
        var b = Array("%PDF-1.5\n%".utf8) + [UInt8](repeating: 0x78, count: 300) + [0x0A]
        let off1 = b.count
        b += Array("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n".utf8)
        let off4 = b.count
        b += Array("4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length \(length4) >>\nstream\n3 0 << >>\nendstream\nendobj\n".utf8)
        let off2 = b.count
        func row(_ t: UInt8, _ f2: Int, _ f3: UInt8) -> [UInt8] { [t, UInt8(f2 >> 8 & 0xFF), UInt8(f2 & 0xFF), f3] }
        let rows = row(0, 0, 0xFF) + row(1, off1, 0) + row(1, off2, 0) + (row3 ?? row(2, 4, 0)) + (row4 ?? row(1, off4, 0))
        b += Array("2 0 obj\n<< /Type /XRef /Size \(size) /W [1 2 1] /Index [0 5] /Root 1 0 R /Length \(rows.count) >>\nstream\n".utf8)
        b += rows
        b += Array("\nendstream\nendobj\nstartxref\n\(off2)\n%%EOF\n".utf8)
        return b
    }

    func testObjStmGraph() throws {
        let inStm: (UInt8) -> [UInt8] = { [2, 0, $0, 0] }
        let cases: [(String, [UInt8], Bool)] = [
            ("legitimate ObjStm", xrefStreamPDF("5", "9"), false),
            ("/Size = max", xrefStreamPDF(String(Structure.maxXrefSize), "9"), false),
            ("obj 3 is its own container", xrefStreamPDF("5", "9", row3: inStm(3)), true),
            ("ObjStm 4 inside ObjStm 3 (mutual)", xrefStreamPDF("5", "9", row4: inStm(3)), true),
            ("ObjStm /Length inside its own ObjStm", xrefStreamPDF("5", "3 0 R"), true),
            ("/Size 10^10", xrefStreamPDF("10000000000", "9"), true),
        ]
        for (name, doc, bad) in cases {
            if bad {
                XCTAssertThrowsError(try Structure.check(doc), name)
            } else {
                XCTAssertNoThrow(try Structure.check(doc), name)
                let r = try PdfReader(doc)
                XCTAssertNotNil(try r.object(PdfRef(id: 3, gen: 0)).dict, name)
            }
        }
    }

    func testEncryptScan() async throws {
        for (s, want) in [("/Encrypt 5 0 R", true), ("/Encrypt<</V 5>>", true), ("/Encrypt\n<<", true),
                          ("/EncryptMetadata false", false), ("/Encrypt 5 R", false), ("/Encrypt5 0 R", false)] {
            XCTAssertEqual(Structure.hasEncryptRef(Array(s.utf8)), want, s)
        }
        // A document the reader cannot open but with a direct /Encrypt dictionary → PDF_ENCRYPTED (#4), not PDF_INVALID.
        let m = try g.manifest()
        let o = EidPades.PrepareOptions(signerCert: try g.certDER("citizen"),
                                        chain: [try g.certDER("04"), try g.certDER("03"), try g.certDER("02")],
                                        signingTime: m.signingTime)
        let doc = Data("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt << /Filter /Standard /V 5 >> >>\n".utf8)
        XCTAssertThrowsError(try EidPades.prepare(pdf: doc, options: o)) {
            XCTAssertEqual(($0 as? EidPadesError)?.code, .pdfEncrypted)
        }
    }

    // MARK: - Revocation evidence (complete's OCSP/CRL collection)

    /// The final Catalog's /DSS OCSPs and CRLs.
    private func dss(_ name: String) throws -> (ocsps: [[UInt8]], crls: [[UInt8]]) {
        let r = try PdfReader(try g.file("validate/\(name).pdf"))
        let root = try XCTUnwrap(try r.resolve(r.trailer["Root"]).dict)
        let d = try XCTUnwrap(try r.resolve(root["DSS"]).dict)
        func streams(_ k: String) throws -> [[UInt8]] {
            try (try r.resolve(d[k]).array ?? []).map { try r.decodedStream(try r.resolve($0)) }
        }
        return (try streams("OCSPs"), try streams("CRLs"))
    }

    /// Serves the DSS evidence as the responders would: OCSP by the requested serial, CRL by the CDP owner's issuer
    /// (else a CRL of an issuer outside the chain — the "wrong issuer" case).
    private struct DSSTransport: EidPadesTransport {
        let ocsps: [[UInt8]]
        let crls: [[UInt8]]
        let chain: [X509Cert]
        func send(method: String, url: URL, contentType: String?, body: Data?) async throws -> Data {
            if method == "POST" {
                let req = try DER.parse([UInt8](body ?? Data()))
                let serial = try req.child(0).child(0).child(0).child(0).child(3).unsignedInteger
                for der in ocsps where Self.serials(der).contains(serial) { return Data(der) }
                throw DERError("404")
            }
            guard let owner = chain.first(where: { $0.crlDistributionPoints.contains(url.absoluteString) }) else { throw DERError("404") }
            let parsed = crls.compactMap { der in CRL.parse(der).map { (der, $0) } }
            if let hit = parsed.first(where: { $0.1.rawIssuer == owner.rawIssuer }) { return Data(hit.0) }
            if let foreign = parsed.first(where: { p in !chain.contains { $0.rawIssuer == p.1.rawIssuer } }) { return Data(foreign.0) }
            throw DERError("404")
        }

        static func serials(_ der: [UInt8]) -> [[UInt8]] {
            guard let rb = try? DER.parse(der).child(1).child(0), let basic = try? DER.parse(rb.child(1).value),
                  var t = try? basic.child(0).children() else { return [] }
            if t.first?.tag == 0xA0 { t.removeFirst() }
            return ((try? t[2].children()) ?? []).compactMap { try? $0.child(0).child(3).unsignedInteger }
        }
    }

    func testRevocationEvidenceV4() async throws {
        let chain = try ["citizen", "04", "03", "02"].map { try X509Cert(der: [UInt8](try g.certDER($0))) }
        let root = try X509Cert(der: [UInt8](try g.certDER("root")))
        let now = ISO8601DateFormatter().date(from: "2026-10-14T04:00:30Z")!  // validate manifest `time`
        enum Want { case ok, unavailable, revoked }
        let cases: [(String, Want)] = [
            ("dss-ocsp-stale", .unavailable), ("dss-ocsp-expired", .unavailable), ("dss-ocsp-future", .unavailable),
            ("dss-ocsp-other-serial", .unavailable), ("dss-ocsp-other-issuer", .unavailable),
            ("dss-ocsp-revoked", .revoked), ("dss-ocsp-revoked-after-signing", .revoked), ("dss-crl-revoked", .revoked),
            ("dss-crl-wrong-issuer", .unavailable), ("dss-crl-only", .ok), ("dss-no-revocation", .unavailable),
        ]
        for (name, want) in cases {
            let (ocsps, crls) = try dss(name)
            let f = Fetcher(DSSTransport(ocsps: ocsps, crls: crls, chain: chain))
            do {
                _ = try await LTV.collect(f, now: now, after: .distantPast, roots: [root], chains: [chain])
                XCTAssertEqual(want, .ok, name)
            } catch let e as CertificateRevoked {
                XCTAssertEqual(want, .revoked, "\(name): \(e)")
                XCTAssertEqual(e.ref, "serial 3ed", name)
            } catch {
                XCTAssertEqual(want, .unavailable, "\(name): \(error)")
                // The citizen is named by serial, never by CN (PII).
                XCTAssertTrue("\(error)".contains("serial 3ed"), "\(name): \(error)")
                XCTAssertFalse("\(error)".contains("TESTOV"), "\(name): \(error)")
            }
        }
    }

    /// `complete` with a revoked citizen OCSP: LTV_UNAVAILABLE, `certificateRevoked`, not retryable (Go
    /// `ErrCertificateRevoked`) — before, a revoked OCSP was skipped and a clean CRL completed the DSS.
    func testCompleteRevokedIsFinal() async throws {
        let m = try g.manifest()
        let c = try XCTUnwrap(m.cases.first { $0.name == "quartz-pdf13" })
        let citizen = try X509Cert(der: [UInt8](try g.certDER("citizen")))
        let o = EidPades.PrepareOptions(signerCert: Data(citizen.raw),
                                        chain: [try g.certDER("04"), try g.certDER("03"), try g.certDER("02")],
                                        signingTime: m.signingTime, docId: c.prepare.docId, verifyPage: true,
                                        fileName: c.prepare.fileName)
        let p = try EidPades.prepare(pdf: Data(try g.file(c.input)), options: o)
        let revoked = try dss("dss-ocsp-revoked").ocsps.first { DSSTransport.serials($0).contains(DER.minimal(citizen.serial)) }
        struct Override: EidPadesTransport {
            let base: GoldenTests.Replay
            let ocspURL: String
            let body: Data
            func send(method: String, url: URL, contentType: String?, body b: Data?) async throws -> Data {
                if method == "POST", url.absoluteString == ocspURL { return body }
                return try await base.send(method: method, url: url, contentType: contentType, body: b)
            }
        }
        var co = EidPades.CompleteOptions(tsaUrl: "http://tsa.pki.test/", roots: [try g.certDER("root")],
                                          transport: Override(base: GoldenTests.Replay(m: m.http, dir: GoldenTests.dir),
                                                              ocspURL: try XCTUnwrap(citizen.ocspServers.first),
                                                              body: Data(try XCTUnwrap(revoked))))
        let now = m.now
        co.now = { now }
        co.sleep = { _ in }
        let n = GoldenTests.nonce(c.name)
        co.nonce = { n }
        do {
            _ = try await EidPades.complete(state: p.state, signature: GoldenTests.unhex(try XCTUnwrap(c.expect.signature)), options: co)
            XCTFail("revoked certificate completed")
        } catch let e as EidPadesError {
            XCTAssertEqual(e.code, .ltvUnavailable, e.message)
            XCTAssertTrue(e.certificateRevoked, e.message)
            XCTAssertFalse(e.retryable)
            XCTAssertFalse(e.message.contains("TESTOV"), e.message)
        }
    }

    /// The output self-check accepts the real output and rejects one whose new signature is not what was prepared.
    func testSelfCheck() async throws {
        let m = try g.manifest()
        let c = try XCTUnwrap(m.cases.first { $0.name == "quartz-pdf13-second" })
        let first = try XCTUnwrap(m.cases.first { $0.name == "quartz-pdf13" })
        let o = { (cs: GoldenTests.Case) in
            EidPades.PrepareOptions(signerCert: try self.g.certDER("citizen"),
                                    chain: [try self.g.certDER("04"), try self.g.certDER("03"), try self.g.certDER("02")],
                                    reason: cs.prepare.reason, claimedRole: cs.prepare.claimedRole,
                                    signingTime: m.signingTime, docId: cs.prepare.docId,
                                    verifyPage: cs.prepare.verifyPage ?? false, fileName: cs.prepare.fileName, lang: cs.prepare.lang)
        }
        func run(_ cs: GoldenTests.Case, _ input: Data) async throws -> (EidPades.Completed, State) {
            let p = try EidPades.prepare(pdf: input, options: try o(cs))
            var co = EidPades.CompleteOptions(tsaUrl: "http://tsa.pki.test/", roots: [try g.certDER("root")],
                                              transport: GoldenTests.Replay(m: m.http, dir: GoldenTests.dir))
            let now = m.now, n = GoldenTests.nonce(cs.name)
            co.now = { now }
            co.sleep = { _ in }
            co.nonce = { n }
            let done = try await EidPades.complete(state: p.state, signature: GoldenTests.unhex(try XCTUnwrap(cs.expect.signature)), options: co)
            return (done, try State.decode([UInt8](p.state)))
        }
        let (d1, _) = try await run(first, Data(try g.file(first.input)))
        let (d2, st) = try await run(c, d1.pdf)
        let out = [UInt8](d2.pdf)
        let signed = Array(out[0..<(st.byteRange[2] + st.byteRange[3])])
        let prior = try EidPades.selfCheck(out, signed: signed, cms: [UInt8](d2.cms), state: st)
        XCTAssertEqual(prior.map { Crypto.hex(Crypto.sha256($0.cms)) }, d2.priorCmsSha256)
        XCTAssertThrowsError(try EidPades.selfCheck(out, signed: signed, cms: [UInt8](d1.cms), state: st))
        var wrongCount = st
        wrongCount.revIndex = 1
        XCTAssertThrowsError(try EidPades.selfCheck(out, signed: signed, cms: [UInt8](d2.cms), state: wrongCount))
        XCTAssertThrowsError(try EidPades.selfCheck(Array(out[0..<signed.count]), signed: signed, cms: [UInt8](d2.cms), state: st))
        var tampered = out
        tampered[st.byteRange[1] - 10] ^= 1   // a byte covered by the new signature
        XCTAssertThrowsError(try EidPades.selfCheck(tampered, signed: Array(tampered[0..<signed.count]), cms: [UInt8](d2.cms), state: st))
    }

    // MARK: - Chain building (Go CheckSignatureFrom / Verify)

    func testIssuerMustBeCA() throws {
        let citizen = try X509Cert(der: [UInt8](try g.certDER("citizen")))
        let ca04 = try X509Cert(der: [UInt8](try g.certDER("04")))
        XCTAssertTrue(ca04.isCA && ca04.basicConstraintsValid)
        XCTAssertTrue(citizen.isSigned(by: ca04))
        XCTAssertFalse(citizen.mayIssue(X509Cert.keyUsageCertSign), "an end-entity certificate cannot issue")
        // A certificate "issued" by the citizen (subject = citizen) never chains, whatever the signature.
        XCTAssertFalse(ca04.isSigned(by: citizen))
        // pathLenConstraint: n CA certificates below are allowed, n + 1 are not.
        for name in ["04", "03", "02", "root"] {
            let c = try X509Cert(der: [UInt8](try g.certDER(name)))
            XCTAssertTrue(c.mayIssue(X509Cert.keyUsageCertSign), name)
            if let max = c.maxPathLen {
                XCTAssertTrue(c.allowsPath(below: max), name)
                XCTAssertFalse(c.allowsPath(below: max + 1), name)
            }
        }
    }
}
