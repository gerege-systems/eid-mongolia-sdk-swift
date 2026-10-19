# eID Mongolia — PAdES SDK (Swift)

`GeregeEIDPades` — eID Mongolia-ийн **client-side PAdES** (PDF гарын үсэг) Swift сан. PDF хэзээ ч eID сервер рүү
явахгүй: апп PDF-ийг локалд бэлдэж (`prepare`), зөвхөн 32 байт DTBS-ийг иргэний утас эсвэл USB токеноор гарын
үсэглүүлээд, гарын үсгийг PDF-д суулгана (`complete`: RFC 3161 цагийн тамга + OCSP/CRL + DSS → PAdES B-LT).

- iOS 14+ / macOS 13+ (Mac App Store sandbox-д ажиллана)
- Гуравдагч хамааралгүй — CryptoKit, Security.framework, системийн zlib
- Профайл `pades-client/1` — Go reference ([`eid-mongolia-sdk-go`](https://github.com/gerege-systems/eid-mongolia-sdk-go)
  `pades`)-тэй **байт-ижил** гаралт (golden vector-оор CI-д шалгагдана)
- Android хувилбар: [`eid-mongolia-sdk-android`](https://github.com/gerege-systems/eid-mongolia-sdk-android) — API 1:1

## Суулгах (Swift Package Manager)

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/gerege-systems/eid-mongolia-sdk-swift.git", from: "0.5.0")
],
targets: [
    .target(name: "App", dependencies: [
        .product(name: "GeregeEIDPades", package: "eid-mongolia-sdk-swift")
    ])
]
```

Хувилбар: хамгийн сүүлийн tag-ийг ашиглана ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-swift/tags)).

Xcode: **File → Add Package Dependencies…** → `https://github.com/gerege-systems/eid-mongolia-sdk-swift.git`.

## Хэрэглээ

```swift
import GeregeEIDPades

// 1) Сүлжээгүй: PDF-ийг бэлдэж DTBS гаргана
let prepared = try EidPades.prepare(pdf: pdf, options: .init(signerCert: signCertDER, verifyPage: true))
// prepared.state-ийг хадгалж болно; prepared.dtbs-ийг (32 байт) утас/токеноор гарын үсэглүүлнэ

// 2) TSA + OCSP/CRL + DSS
let done = try await EidPades.complete(state: prepared.state, signature: sig)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.signerCert, done.fileName
let body = try JSONEncoder().encode(done.registration(medium: .phone, sessionId: sessionID))
// → RP backend нь body-г eID-д ЯГ ХЭВЭЭР бүртгэнэ (POST /pdf/signatures)
```

- `prepare`: урьдчилсан шалгуур (шифрлэлт, DocMDP P=1, өмнөх гарын үсэг, ≤ 16), эхний eID гарын үсэгт
  `verifyPage: true` бол баталгаажуулалтын (QR) хуудас (`lang`: `mn` анхдагч / `en`; NotoSans subset фонт, OFL —
  `Sources/GeregeEIDPades/Resources/fonts/OFL.txt`), гарын үсгийн revision, signedAttrs (+ `claimedRole`) → DTBS.
- `complete`: иргэний гарын үсгийг DTBS дээр шалгана (RSA PKCS#1 v1.5, ECDSA) → RFC 3161 → CMS → embed →
  OCSP/CRL → DSS revision.
- `CompleteOptions.transport` — өөрийн HTTP (proxy, sandbox); анхдагч нь URLSession (10 с, redirect-гүй, ≤ 4 MiB).
- Алдаа: `EidPadesError.code` — бүх SDK-д ижил тогтвортой код (`PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED`,
  `PDF_FOREIGN_SIGNATURE`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`, `STATE_INVALID`, …).
  `retryable` — TSA/LTV түр алдаа; `certificateRevoked` — гинжийн гэрчилгээ цуцлагдсан (эцсийн).
- Бүрэн validator энэ санд байхгүй — шалгалтыг backend-д Go SDK-ээр хийнэ.

Интеграцийн баримт: <https://developer.eidmongolia.mn>.

## Conformance

`Tests/GeregeEIDPadesTests/golden/` — Go reference-ийн golden vector (оролтын PDF, **зөвхөн тестийн** PKI гэрчилгээ,
тогтмол TSA/OCSP/CRL хариу); хувийн түлхүүр хасагдсан. Эх tag нь `golden/SOURCE`-д.

```sh
scripts/sync-pades-golden.sh --check   # vendored = Go репогийн tag
swift test
```

## Эх сурвалж ба хувь нэмэр

Энэ репо нь eID Mongolia-ийн дотоод репоны **толин хуулбар** (`sync from ca <sha>` commit-ууд). Алдаа, санал бол
GitHub Issues-д бичнэ үү; PR-ийг дотоод репод шилжүүлж оруулна.

## License

MIT — [LICENSE](LICENSE). Фонт: SIL Open Font License 1.1 (`Sources/GeregeEIDPades/Resources/fonts/OFL.txt`).

---

### English

Client-side PAdES signing for eID Mongolia. The PDF never leaves the device: `prepare` builds the signature revision
and returns a 32-byte DTBS to be signed by the citizen's phone or USB token; `complete` embeds the signature with an
RFC 3161 timestamp, OCSP/CRL and DSS (PAdES B-LT). Output is byte-identical to the Go reference
(`gerege-systems/eid-mongolia-sdk-go`, profile `pades-client/1`), enforced by golden vectors in CI.
iOS 14+ / macOS 13+, no third-party dependencies. Install via SwiftPM:
`.package(url: "https://github.com/gerege-systems/eid-mongolia-sdk-swift.git", from: "0.5.0")` (use the latest tag), product
`GeregeEIDPades`. This repository is a read-only mirror; please file issues here.
