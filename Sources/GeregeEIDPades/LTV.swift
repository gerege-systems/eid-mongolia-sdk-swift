import Foundation

/// DSS (B-LT) collection — port of the Go reference `pades/ltv.go`: for every certificate of the chains (except
/// roots) the AIA OCSP (SHA-1 CertID) and CDP CRL are fetched and checked — signature/issuer, CertID, freshness
/// (`Revocation.freshAt` at the current time); fail-closed when a certificate has no valid revocation data. The leaf
/// OCSP must be produced after the timestamp (thisUpdate > genTime). An issuer-signed "revoked" answer (OCSP or CRL)
/// throws `CertificateRevoked` at once — no other URL/CRL is tried for a "good" answer, no retry.
enum LTV {
    struct NotFresh: Error, CustomStringConvertible {
        let ref: String
        var description: String { "OCSP thisUpdate is not after the timestamp (" + ref + ")" }
    }

    static let ocspAfterTS: TimeInterval = 2
    static let ocspWaitMax: TimeInterval = 5
    static let ocspRetry: TimeInterval = 1

    /// Waits until genTime (whole second) + 2 s (≤ 5 s total), retries on stale leaf OCSP every second.
    static func collectWithWait(_ f: Fetcher, now: () -> Date, sleep: (TimeInterval) async throws -> Void,
                                genTime: Date, roots: [X509Cert], chains: [[X509Cert]]) async throws -> PadesDSS.Material {
        var waited: TimeInterval = 0
        let genSecond = Date(timeIntervalSince1970: floor(genTime.timeIntervalSince1970))
        var d = min(genSecond.addingTimeInterval(ocspAfterTS).timeIntervalSince(now()), ocspWaitMax)
        while true {
            if d > 0 {
                try await sleep(d)
                waited += d
            }
            do {
                return try await collect(f, now: now(), after: genTime, roots: roots, chains: chains)
            } catch is NotFresh where waited + ocspRetry <= ocspWaitMax {
                d = ocspRetry
            }
        }
    }

    static func collect(_ f: Fetcher, now: Date, after: Date, roots: [X509Cert],
                        chains: [[X509Cert]]) async throws -> PadesDSS.Material {
        var m = PadesDSS.Material()
        func addCert(_ c: X509Cert) { if !m.certs.contains(c.raw) { m.certs.append(c.raw) } }
        let pool = chains.flatMap { $0 }
        func issuerOf(_ c: X509Cert) -> X509Cert? { (pool + roots).first { c.isSigned(by: $0) } }
        var seen = Set<[UInt8]>()
        for ch in chains {
            for (i, c) in ch.enumerated() {
                if seen.contains(c.raw) || roots.contains(c) { continue }
                seen.insert(c.raw)
                addCert(c)
                guard let issuer = issuerOf(c) else { throw DERError("LTV: issuer of \(c.serialRef) not found") }
                var ok = false
                var stale = false
                let fresh: Date? = i == 0 ? after : nil
                for u in c.ocspServers {
                    let der: [UInt8], r: OCSP.Response
                    do {
                        (der, r) = try await fetchOCSP(f, u, cert: c, issuer: issuer, now: now, after: fresh)
                    } catch let e as CertificateRevoked {
                        throw e
                    } catch is NotFresh {
                        stale = true
                        continue
                    } catch {
                        continue
                    }
                    if !m.ocsps.contains(der) { m.ocsps.append(der) }
                    if let rc = r.certificate, rc != issuer { addCert(rc) }  // delegated responder
                    ok = true
                    break
                }
                for u in c.crlDistributionPoints {
                    guard let der = try? await f.fetch("GET", u) else { continue }
                    if try CRL.covers(der, cert: c, issuer: issuer, now: now) {
                        if !m.crls.contains(der) { m.crls.append(der) }
                        ok = true
                    }
                }
                if !ok {
                    if stale { throw NotFresh(ref: c.serialRef) }
                    throw DERError("LTV: no valid OCSP/CRL for \(c.serialRef)")
                }
                if i == 0, stale, !c.ocspServers.isEmpty, !hasFreshOCSP(m.ocsps, c, issuer, after) {
                    // The leaf OCSP is not after genTime — retried by the CA rule even with a CRL.
                    throw NotFresh(ref: c.serialRef)
                }
            }
        }
        return m
    }

    /// Go `fetchOCSP`: SHA-1 CertID request; response signed by the issuer (or a delegated id-kp-OCSPSigning
    /// responder), CertID = this certificate + issuer, revoked → `CertificateRevoked`, good and fresh now, thisUpdate
    /// after `after` (when given).
    static func fetchOCSP(_ f: Fetcher, _ url: String, cert c: X509Cert, issuer: X509Cert, now: Date,
                          after: Date?) async throws -> ([UInt8], OCSP.Response) {
        let der = try await f.fetch("POST", url, contentType: "application/ocsp-request",
                                    body: OCSP.request(cert: c, issuer: issuer))
        let r = try OCSP.parse(der, cert: c, issuer: issuer)
        guard OCSP.responderOK(r, issuer: issuer) else { throw DERError("OCSP responder EKU is not OCSPSigning") }
        guard OCSP.certIDMatches(der, cert: c, issuer: issuer) else { throw DERError("OCSP CertID is not this certificate's") }
        if r.status == .revoked { throw CertificateRevoked(ref: c.serialRef) }
        guard r.status == .good, Revocation.freshAt(thisUpdate: r.thisUpdate, nextUpdate: r.nextUpdate, at: now, now: now) else {
            throw DERError("OCSP \(c.serialRef): not good or not fresh")
        }
        if let after, !(r.thisUpdate > after) { throw NotFresh(ref: c.serialRef) }
        return (der, r)
    }

    private static func hasFreshOCSP(_ list: [[UInt8]], _ c: X509Cert, _ issuer: X509Cert, _ after: Date) -> Bool {
        list.contains {
            ((try? OCSP.parse($0, cert: c, issuer: issuer))?.thisUpdate ?? .distantPast) > after
                && OCSP.certIDMatches($0, cert: c, issuer: issuer)
        }
    }
}
