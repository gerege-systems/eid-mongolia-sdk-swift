// LTV revocation collection order by certificate role: the end entity (first certificate of a chain) asks its OCSP
// first (full timeout) and then its CRL; a CA certificate fetches its CRL first and sends no OCSP request at all when the
// CRL is valid (a dead CA responder — ocsp.esign.gov.mn accepts the connection and never answers — is never contacted),
// falling back to OCSP only without a valid CRL. Fail-closed, revoked fatal, caller cancellation propagated.
// Golden PKI: citizen ← 04 ← 03 ← 02 ← root; OCSP only for citizen (ocsp.pki.test/04) and 04 (ocsp.pki.test/03).
import Foundation
import XCTest
@testable import GeregeEIDPades

final class LTVOrderTests: XCTestCase {
    private let g = GoldenTests()

    /// Requests seen ("METHOD url", in order) and requests in flight.
    private final class Recorder: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        private var seen: [String] = []
        func enter(_ key: String) { lock.lock(); n += 1; seen.append(key); lock.unlock() }
        func leave() { lock.lock(); n -= 1; lock.unlock() }
        var inFlight: Int { lock.lock(); defer { lock.unlock() }; return n }
        var requests: [String] { lock.lock(); defer { lock.unlock() }; return seen }
    }

    /// golden/http replay with per-request behaviour (key "METHOD url").
    private struct Fake: EidPadesTransport {
        enum Act: Sendable { case hang, fail, body([UInt8]), delay(TimeInterval, [UInt8]?), failAfter(TimeInterval) }
        let base: GoldenTests.Replay
        var acts: [String: Act] = [:]
        let rec = Recorder()

        func send(method: String, url: URL, contentType: String?, body: Data?) async throws -> Data {
            let key = "\(method) \(url.absoluteString)"
            rec.enter(key)
            defer { rec.leave() }
            switch acts[key] {
            case .hang?:
                try await Task.sleep(nanoseconds: 120_000_000_000)
                throw DERError("hang ended")
            case .fail?:
                throw DERError("404")
            case .failAfter(let s)?:
                try await Task.sleep(nanoseconds: UInt64(s * 1e9))
                throw DERError("timed out")
            case .body(let b)?:
                return Data(b)
            case .delay(let s, let b)?:
                try await Task.sleep(nanoseconds: UInt64(s * 1e9))
                if let b { return Data(b) }
            case nil:
                break
            }
            return try await base.send(method: method, url: url, contentType: contentType, body: body)
        }
    }

    private struct Fx {
        let now: Date
        let replay: GoldenTests.Replay
        let citizen, ca04, ca03, root: X509Cert
        let chain: [X509Cert]
        var citizenOCSP: String { citizen.ocspServers[0] }
        var ca04OCSP: String { ca04.ocspServers[0] }
        var citizenCRL: String { citizen.crlDistributionPoints[0] }
        var ca04CRL: String { ca04.crlDistributionPoints[0] }

        func collect(_ t: EidPadesTransport) async throws -> PadesDSS.Material {
            try await LTV.collect(Fetcher(t), now: now, after: .distantPast, roots: [root], chains: [chain])
        }

        func post(_ c: X509Cert, _ issuer: X509Cert) async throws -> [UInt8] {
            [UInt8](try await replay.send(method: "POST", url: URL(string: c.ocspServers[0])!,
                                          contentType: "application/ocsp-request", body: Data(OCSP.request(cert: c, issuer: issuer))))
        }

        func get(_ url: String) async throws -> [UInt8] {
            [UInt8](try await replay.send(method: "GET", url: URL(string: url)!, contentType: nil, body: nil))
        }
    }

    private func load() throws -> Fx {
        let m = try g.manifest()
        func cert(_ n: String) throws -> X509Cert { try X509Cert(der: [UInt8](try g.certDER(n))) }
        let citizen = try cert("citizen"), ca04 = try cert("04"), ca03 = try cert("03"), ca02 = try cert("02")
        return Fx(now: m.now, replay: GoldenTests.Replay(m: m.http, dir: GoldenTests.dir), citizen: citizen, ca04: ca04,
                  ca03: ca03, root: try cert("root"), chain: [citizen, ca04, ca03, ca02])
    }

    /// golden/validate/<name>.pdf /DSS OCSPs and CRLs.
    private func dss(_ name: String) throws -> (ocsps: [[UInt8]], crls: [[UInt8]]) {
        let r = try PdfReader(try g.file("validate/\(name).pdf"))
        let catalog = try XCTUnwrap(try r.resolve(r.trailer["Root"]).dict)
        let d = try XCTUnwrap(try r.resolve(catalog["DSS"]).dict)
        func streams(_ k: String) throws -> [[UInt8]] {
            try (try r.resolve(d[k]).array ?? []).map { try r.decodedStream(try r.resolve($0)) }
        }
        return (try streams("OCSPs"), try streams("CRLs"))
    }

    private func elapsed(since t: Date) -> TimeInterval { Date().timeIntervalSince(t) }

    /// Healthy chain: leaf OCSP + every CRL; the CA certificate 04 (valid CRL) never contacts its OCSP responder, even
    /// one that would hang.
    func testCAWithValidCRLSendsNoOCSP() async throws {
        let fx = try load()
        let ocspCitizen = try await fx.post(fx.citizen, fx.ca04)
        let crlCitizen = try await fx.get(fx.citizenCRL), crl04 = try await fx.get(fx.ca04CRL)
        let t = Fake(base: fx.replay, acts: ["POST \(fx.ca04OCSP)": .hang])
        let start = Date()
        let got = try await fx.collect(t)
        XCTAssertLessThan(elapsed(since: start), 5)
        XCTAssertFalse(t.rec.requests.contains("POST \(fx.ca04OCSP)"), "\(t.rec.requests)")
        XCTAssertEqual(t.rec.requests.filter { $0.hasPrefix("POST") }, ["POST \(fx.citizenOCSP)"])
        XCTAssertEqual(got.ocsps, [ocspCitizen])
        XCTAssertEqual(got.crls.count, 4)   // 04, 03, 02, root CRLs, chain order
        XCTAssertEqual(Array(got.crls.prefix(2)), [crlCitizen, crl04])
        XCTAssertEqual(Array(got.certs.prefix(4)), fx.chain.map(\.raw))
        XCTAssertEqual(t.rec.inFlight, 0)
    }

    /// Leaf: OCSP is asked first, then its CRL.
    func testLeafAsksOCSPFirst() async throws {
        let fx = try load()
        let t = Fake(base: fx.replay)
        _ = try await fx.collect(t)
        XCTAssertEqual(Array(t.rec.requests.prefix(2)), ["POST \(fx.citizenOCSP)", "GET \(fx.citizenCRL)"])
    }

    /// CA certificate without a valid CRL (missing, or not its issuer's) → OCSP fallback, embedded.
    func testCAWithoutValidCRLFallsBackToOCSP() async throws {
        let fx = try load()
        // golden/http has no OCSP for 04 since v11 (its CRL is used); the validate DSS still carries one.
        let ocsp04 = try XCTUnwrap(try dss("dss-crl-only").ocsps.first {
            (try? OCSP.parse($0, cert: fx.ca04, issuer: fx.ca03)) != nil
        })
        let wrongIssuer = try await fx.get(fx.citizenCRL)  // 04's CRL, not 03's
        for act: Fake.Act in [.fail, .body(wrongIssuer)] {
            let t = Fake(base: fx.replay, acts: ["GET \(fx.ca04CRL)": act, "POST \(fx.ca04OCSP)": .body(ocsp04)])
            let got = try await fx.collect(t)
            XCTAssertTrue(t.rec.requests.contains("POST \(fx.ca04OCSP)"))
            XCTAssertTrue(got.ocsps.contains(ocsp04))
            XCTAssertEqual(got.crls.count, 3)
        }
        // Neither CRL nor OCSP → fail-closed.
        let t = Fake(base: fx.replay, acts: ["GET \(fx.ca04CRL)": .fail, "POST \(fx.ca04OCSP)": .fail])
        do {
            _ = try await fx.collect(t)
            XCTFail("CA certificate without revocation data accepted")
        } catch {
            XCTAssertTrue("\(error)".contains("no valid OCSP/CRL for serial 3ec"), "\(error)")
        }
    }

    /// A slow leaf OCSP is awaited and embedded (full timeout), even though its CRL is valid.
    func testSlowLeafOCSPIsAwaited() async throws {
        let fx = try load()
        let ocspCitizen = try await fx.post(fx.citizen, fx.ca04)
        let t = Fake(base: fx.replay, acts: ["POST \(fx.citizenOCSP)": .delay(0.6, nil)])
        let start = Date()
        let got = try await fx.collect(t)
        XCTAssertGreaterThanOrEqual(elapsed(since: start), 0.55)
        XCTAssertEqual(got.ocsps, [ocspCitizen])
    }

    /// A dead leaf OCSP (transport timeout) → its CRL after the timeout.
    func testDeadLeafOCSPFallsBackToCRL() async throws {
        let fx = try load()
        let crlCitizen = try await fx.get(fx.citizenCRL)
        let t = Fake(base: fx.replay, acts: ["POST \(fx.citizenOCSP)": .failAfter(0.4)])
        let start = Date()
        let got = try await fx.collect(t)
        XCTAssertGreaterThanOrEqual(elapsed(since: start), 0.35)
        XCTAssertTrue(got.ocsps.isEmpty)
        XCTAssertEqual(got.crls.first, crlCitizen)
        // …and without a CRL either → fail-closed.
        let none = Fake(base: fx.replay, acts: ["POST \(fx.citizenOCSP)": .fail, "GET \(fx.citizenCRL)": .fail])
        do {
            _ = try await fx.collect(none)
            XCTFail("leaf without revocation data accepted")
        } catch is CertificateRevoked {
            XCTFail("not revoked")
        } catch {
            XCTAssertTrue("\(error)".contains("no valid OCSP/CRL for serial 3ed"), "\(error)")
        }
    }

    /// Revoked is fatal from either source: the leaf's CRL lists it (even with a good OCSP), or its OCSP says revoked
    /// (even with a clean CRL).
    func testRevokedFromEitherSourceIsFatal() async throws {
        let fx = try load()
        let revokedCRL = try XCTUnwrap(try dss("dss-crl-revoked").crls.first {
            guard let p = CRL.parse($0) else { return false }
            return CRL.isFor(p, cert: fx.citizen, issuer: fx.ca04) && p.revoked.contains(DER.minimal(fx.citizen.serial))
        })
        let revokedOCSP = try XCTUnwrap(try dss("dss-ocsp-revoked").ocsps.first {
            (try? OCSP.parse($0, cert: fx.citizen, issuer: fx.ca04))?.status == .revoked
        })
        for acts: [String: Fake.Act] in [["GET \(fx.citizenCRL)": .body(revokedCRL)],
                                         ["POST \(fx.citizenOCSP)": .body(revokedOCSP)]] {
            do {
                _ = try await fx.collect(Fake(base: fx.replay, acts: acts))
                XCTFail("revoked certificate collected (\(acts.keys))")
            } catch let e as CertificateRevoked {
                XCTAssertEqual(e.ref, "serial 3ed")
            }
        }
    }

    func testGarbageLeafOCSPFallsBackToCRL() async throws {
        let fx = try load()
        let got = try await fx.collect(Fake(base: fx.replay, acts: ["POST \(fx.citizenOCSP)": .body([0x30, 0x03, 0x02, 0x01, 0x00])]))
        XCTAssertTrue(got.ocsps.isEmpty)
        XCTAssertEqual(got.crls.count, 4)
    }

    func testCallerCancellationIsPropagated() async throws {
        let fx = try load()
        let t = Fake(base: fx.replay, acts: ["POST \(fx.citizenOCSP)": .hang])
        let start = Date()
        let task = Task { try await fx.collect(t) }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("cancelled collect returned")
        } catch is CancellationError {
        }
        XCTAssertLessThan(elapsed(since: start), 5)
        XCTAssertEqual(t.rec.inFlight, 0)
    }
}
