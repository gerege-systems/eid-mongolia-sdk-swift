import Foundation

/// HTTP for TSA / OCSP / CRL during `complete`. Inject your own for a proxy, sandbox or tests. Must throw for a
/// non-200 status. Requests go only to the configured TSA and to the certificates' AIA/CDP URLs.
public protocol EidPadesTransport: Sendable {
    func send(method: String, url: URL, contentType: String?, body: Data?) async throws -> Data
}

/// URLSession transport: 10 s timeout, no redirects, response ≤ 4 MiB (Go reference `fetch.go`).
public struct URLSessionPadesTransport: EidPadesTransport {
    public init() {}

    public func send(method: String, url: URL, contentType: String?, body: Data?) async throws -> Data {
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        req.httpMethod = method
        if let contentType { req.setValue(contentType, forHTTPHeaderField: "Content-Type") }
        req.httpBody = body
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200, data.count <= 4 << 20 else {
            throw DERError("\(url.host ?? ""): HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        return data
    }

    private final class NoRedirect: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? { nil }
    }
}

/// One `complete` run's fetcher: http/https only, GET (CRL) responses cached per run.
final class Fetcher {
    private let transport: EidPadesTransport
    private var cache: [String: [UInt8]] = [:]

    init(_ t: EidPadesTransport) { transport = t }

    /// National CRLs (http-only, no CORS) are fetched from eID's https mirror (WIRE.md §3; fixed map). The CRL
    /// signature is still checked against its issuer, so the mirror needs no trust.
    static let crlMirror = [
        "http://esign.gov.mn/MNICA-2022.crl": "https://crl.eidmongolia.mn/MNICA-2022.crl",
        "http://esign.gov.mn/MNRCA-2021.crl": "https://crl.eidmongolia.mn/MNRCA-2021.crl",
    ]

    func fetch(_ method: String, _ rawURL: String, contentType: String? = nil, body: [UInt8]? = nil) async throws -> [UInt8] {
        let raw = Self.crlMirror[rawURL] ?? rawURL
        guard let url = URL(string: raw), let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw DERError("unsupported URL \(raw)")
        }
        if method == "GET", let hit = cache[raw] { return hit }
        let data = try await transport.send(method: method, url: url, contentType: contentType, body: body.map { Data($0) })
        let out = [UInt8](data)
        if method == "GET" { cache[raw] = out }
        return out
    }
}
