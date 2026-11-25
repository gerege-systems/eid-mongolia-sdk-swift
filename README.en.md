[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eID Mongolia — PAdES SDK (Swift)

`GeregeEIDPades` — a Swift library for eID Mongolia **client-side PAdES** (PDF signing). The PDF never goes to the
eID server: the app prepares the PDF locally (`prepare`), has only the 32-byte DTBS signed by the citizen's phone or USB token,
and embeds the signature into the PDF (`complete`: RFC 3161 timestamp + OCSP/CRL + DSS → PAdES B-LT).

- iOS 14+ / macOS 13+ (works in the Mac App Store sandbox)
- No third-party dependencies — CryptoKit, Security.framework, the system zlib
- Profile `pades-client/1` — **byte-identical** output to the Go reference ([`eid-mongolia-sdk-go`](https://github.com/gerege-systems/eid-mongolia-sdk-go)
  `pades`) (checked in CI against golden vectors)
- Android version: [`eid-mongolia-sdk-android`](https://github.com/gerege-systems/eid-mongolia-sdk-android) — API 1:1

## Install (Swift Package Manager)

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/gerege-systems/eid-mongolia-sdk-swift.git", from: "0.10.1")
],
targets: [
    .target(name: "App", dependencies: [
        .product(name: "GeregeEIDPades", package: "eid-mongolia-sdk-swift")
    ])
]
```

Version: use the latest tag ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-swift/tags)).

Xcode: **File → Add Package Dependencies…** → `https://github.com/gerege-systems/eid-mongolia-sdk-swift.git`.

## Usage

```swift
import GeregeEIDPades

// 1) Сүлжээгүй: PDF-ийг бэлдэж DTBS гаргана
// verifyPage: true бол fileName заавал (эс бөгөөс REQUEST_INVALID); эхний eID гарын үсгийг CA зөвхөн хуудастай бүртгэнэ
let prepared = try EidPades.prepare(pdf: pdf, options: .init(signerCert: signCertDER, verifyPage: true,
                                                             fileName: "Гэрээ №1.pdf"))
// prepared.state-ийг хадгалж болно; prepared.dtbs-ийг (32 байт) утас/токеноор гарын үсэглүүлнэ

// 2) TSA + OCSP/CRL + DSS
let done = try await EidPades.complete(state: prepared.state, signature: sig)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.priorRevisionSha256, done.signerCert, done.fileName,
// done.claimedRole
let body = try JSONEncoder().encode(done.registration(medium: .phone, sessionId: sessionID))
// medium-ийг орхивол sessionId-аас: байвал .phone, үгүй бол .token (CA-ийн хос). .phone + sessionId-гүй,
// .token + sessionId, эсвэл claimedRole-той prepare + onBehalfOf-гүй → REQUEST_INVALID (CA руу явахгүй).
// → RP backend нь body-г eID-д ЯГ ХЭВЭЭР бүртгэнэ (POST /pdf/signatures)
```

- `prepare`: preliminary checks (encryption, DocMDP P=1, earlier signatures, ≤ 16); for the first eID signature, with
  `verifyPage: true`, a verification (QR) page (`lang`: `mn` default / `en`; NotoSans subset font, OFL —
  `Sources/GeregeEIDPades/Resources/fonts/OFL.txt`), the signature revision, signedAttrs (+ `claimedRole`) → DTBS.
  `verifyPagePosition: "first"` (0.8.0+) — the page becomes page 1 of the document (default `"last"`); `appearance.page`,
  `suggestPlacement` and `placement.page` count pages of the input PDF (`PAGE_SPEC.md` §8a, `PLACEMENT_SPEC.md` §1b).
- `complete`: verifies the citizen's signature over the DTBS (RSA PKCS#1 v1.5, ECDSA) → RFC 3161 → CMS → embed →
  OCSP/CRL → DSS revision.
- **Visible signature** (optional, Go `APPEARANCE_SPEC.md`): `PrepareOptions.appearance = .init(page: 0, x: 36, y: 36,
  width: 220, height: 64)` — in pt, from the bottom-left corner of the visible page (after `/Rotate`); `page` 0 = the last page of the input that is
  **not** an eID verify page (verify pages of earlier signatures are skipped; `PLACEMENT_SPEC.md` §1a),
  1… stay as explicit numbers. Height ≥ 45 pt; if it leaves the page or the text does not fit, `REQUEST_INVALID`. nil = invisible.
- **Stamp placement** (Go `PLACEMENT_SPEC.md`): `x/y` is the requested position — if it overlaps page content (with a 4 pt margin) it
  moves to the first free position (the mirrored column at the same height → up by 12 pt in the requested column → up in the mirrored column).
  `prepared.placement` (`page`, `x`, `y`, `width`, `height` — pt; `status`: `.requested` | `.moved` | `.overlap` — no free
  spot, at the requested position | `.unscanned` — the page could not be read within the limits, at the requested position). It is advisable to tell the user about `.overlap` /
  `.unscanned` — the signature is valid in every case.
- **Citizen-placed stamp** (`PLACEMENT_SPEC.md` §6a/§6b): `EidPades.suggestPlacement(pdf:appearance:)` — runs `prepare`'s
  placement algorithm without signature, certificate or network → `PlacementSuggestion` (`page`, `x`, `y`,
  `width`, `height`, `status` = `prepared.placement` for the same input; `pageWidth`, `pageHeight`, `pageCount`, `pages[]`
  (the visible size of each page, in pt; 0×0 if unreadable)). The UI shows the default position in a preview, and passes the position the citizen
  dragged to via `SignatureAppearance(…, exact: true)`: the stamp is drawn exactly there and never moves
  (`status`: `.requested`, or `.overlap` if there is content underneath, `.unscanned`; never `.moved`); if it leaves the page,
  `REQUEST_INVALID`. Screen (top-left, `s` px/pt) ↔ appearance: `left = x·s`, `top = (pageHeight − y − height)·s`;
  and back `x = left/s`, `y = pageHeight − top/s − height`. `exact: false` (default) is byte-identical to before.
- `registration(medium:sessionId:onBehalfOf:)` — earlier signatures only by `priorCmsSha256` (if both lists are
  sent, the CA returns 400). On 409 `PRIOR_MISMATCH`, move the matching entries of `priorSignatures` into `priorRevisionSha256` and
  resend (assembled at the CA, mode A). `REQUEST_INVALID` if revIndex is 1 without a page, there is no `fileName`, `medium` ↔ `sessionId` conflict (phone requires sessionId, token requires
  none; if `medium` is omitted it is derived from sessionId), or `onBehalfOf` (NTRMN-…) is empty for a prepare with `claimedRole`.
- Structure checks (Go `PRECHECKS.md` #2a/#2b): nesting > 256, ObjStm cycle, `/Extends` > 64, `/Size` > 2^21 →
  `PDF_INVALID` (in `complete` — `STATE_INVALID`).
- `CompleteOptions.transport` — your own HTTP (proxy, sandbox); the default is URLSession (10 s total deadline, no redirects, ≤ 4 MiB).
- Errors: `EidPadesError.code` — stable codes, the same in every SDK (`PDF_INVALID`, `PDF_ENCRYPTED`, `PDF_LOCKED`,
  `PDF_FOREIGN_SIGNATURE`, `SIGNATURE_INVALID`, `TSA_UNAVAILABLE`, `LTV_UNAVAILABLE`, `STATE_INVALID`, …).
  `retryable` — a transient TSA/LTV error (retry with the same state); `certificateRevoked` — a certificate in the chain was revoked by
  an OCSP/CRL signed by its issuer (`LTV_UNAVAILABLE`, final — `retryable = false`).
- There is no full validator in this library — validation is done in the backend with the Go SDK.

Integration documentation: <https://developer.eidmongolia.mn>.

## Conformance

`Tests/GeregeEIDPadesTests/golden/` — the Go reference's golden vectors (input PDFs, **test-only** PKI certificates,
fixed TSA/OCSP/CRL responses); private keys removed. The source tag is in `golden/SOURCE`.

```sh
scripts/sync-pades-golden.sh --check   # vendored = Go репогийн tag
swift test
```

## Source and contributions

This repo is a **mirror** of eID Mongolia's internal repo (`sync from ca <sha>` commits). Please file bugs and suggestions in
GitHub Issues; PRs are moved over to the internal repo and applied there.

## License

MIT — [LICENSE](LICENSE). Font: SIL Open Font License 1.1 (`Sources/GeregeEIDPades/Resources/fonts/OFL.txt`).
