# Changelog

## 0.9.0 — 2026-10-23

### Added — харагдах гарын үсэгт гарын үсгийн / байгууллагын тамганы зураг (`appearance.signatureImage` / `stampImage`)

- `PdfImage {width, height, color, alpha (zlib), sha256}` — CA-ийн RP хариуны `pdfImage` (гарын үсгийн зураг:
  `GET /v3/person/etsi/{etsi}/signature-image`; тамга: `representations[].stampImage.pdfImage`). Зураг дүрслэлийн `/AP /N`
  form дотор зурагдана; `width = height = 0` → анхдагч хэмжээ 220×64 / 220×110 / 240×147.5. `stampImage` зөвхөн
  `claimedRole`-той. Буруу оролт (alpha-ийн zlib FDICT, DICTID 1 ч) → `REQUEST_INVALID`. `Completed.images` → бүртгэлийн
  `images`; CA одоогийн хадгалсан зурагтай таарахгүй бол 409 `IMAGE_MISMATCH`. Golden = Go reference v0.16.0
  (`pades-golden-v10`).

## 0.8.0 — 2026-10-21

### Added — `PrepareOptions.verifyPagePosition` ("last" | "first")

- `"first"` — баталгаажуулалтын (QR) хуудас баримтын 1-р хуудас болно; анхдагч `"last"` өмнөхтэй байт-ижил; бусад утга
  `REQUEST_INVALID`. `appearance.page`, `suggestPlacement`, `placement.page` оролтын PDF-ийн хуудсаар тоологдоно
  (`PAGE_SPEC.md` §8a, `PLACEMENT_SPEC.md` §1b). Golden = Go reference `pades-golden-v9` (+8 `vpfirst-*` кейс).

## 0.7.1 — 2026-10-21

### Fix — verify хуудасны docId-ийг бодит object generation-оор уншина (golden v8)

- Өмнөх eID гарын үсгийн verify хуудасны Link (`/URI https://ca.eidmongolia.mn/verify/<docId>`) generation ≠ 0 объект
  бол docId олдохгүй байсан (`page: 0` / дараагийн гарын үсэг `REQUEST_INVALID`). Одоо xref-ийн generation-оор —
  Go reference ба Kotlin-той байт-ижил (`PLACEMENT_SPEC.md` §1a «Object generations»).
- Golden = Go reference `pades-golden-v8` (+3 `*-gen1` кейс).

## 0.7.0 — 2026-10-21

### Go reference v0.14.0 (golden v7): `appearance.exact` + `suggestPlacement`

- `SignatureAppearance.exact` (анхдагч false): тамга яг page/x/y/width/height-д зурагдана, хэзээ ч шилжихгүй — иргэн
  урьдчилан харах дээр чирсэн байрлал. `placement.status` = requested | overlap (агуулга дээр) | unscanned; moved үгүй.
  Хуудаснаас гарвал `REQUEST_INVALID`. `exact = false` өмнөхтэй байт-ижил.
- `EidPades.suggestPlacement(pdf, appearance)` → `PlacementSuggestion` (page, x, y, width, height, status, pageWidth,
  pageHeight, pageCount, pages) — prepare-ийн байрлалыг гарын үсэг, сертификат, сүлжээгүйгээр (`PLACEMENT_SPEC.md` §6b).
- Golden = Go reference `pades-golden-v7` (+5 `exact-*` кейс, `expect.suggestion`).

## 0.6.0 — 2026-10-20

### Docs — README нь 0.5.0-ийн API-тай нийцэв

- Жишээ: `verifyPage`-тэй хамт `fileName` (эс бөгөөс `REQUEST_INVALID`).
- Шинэ хэсэг: харагдах гарын үсэг, тамганы байрлал (`placement.status`), `page` 0 = eID verify биш сүүлийн хуудас,
  `registration` (`priorCmsSha256`, 409 `PRIOR_MISMATCH`), бүтцийн хязгаар, цуцлагдсан гэрчилгээ → `retryable = false`.

### Бүртгэлийн medium/claimedRole шалгалт, HTTP нийт timeout

- `registration(medium:sessionId:onBehalfOf:)`: `medium` заавал биш — орхивол `sessionId` байвал phone, эс бөгөөс token (CA-ийн хос). phone + sessionId-гүй
  эсвэл token + sessionId → `REQUEST_INVALID`. Go / TS / .NET SDK-тай ижил.
- `Completed.claimedRole` нэмэгдсэн; claimedRole-той prepare-ийн бүртгэлд `onBehalfOf` хоосон бол `REQUEST_INVALID`
  (CA руу явахгүй).
- `URLSessionPadesTransport`: `timeoutIntervalForResource = 10` (Go `http.Client.Timeout`-тэй ижил).

## 0.5.0 — 2026-10-19 — Go reference v0.12.0 (golden v6): appearance page 0 нь eID verify хуудсыг алгасна

- `appearance.page` 0 / байхгүй = оролтын **eID verify хуудас биш** сүүлийн хуудас: өмнөх гарын үсгүүдийн нэмсэн verify
  хуудсууд (энэ баримтын `https://ca.eidmongolia.mn/verify/<docId>` Link-тэй хуудас) алгасагдана — хоёр дахь гарын
  үсгийн тэмдэг verify хуудсан дээр буухаа больсон. Тодорхой дугаар (1…N) хэвээр.
- Golden = Go reference `pades-golden-v6` (+5 кейс).

## 0.4.0 — 2026-10-19 — Go reference v0.11.0 (golden v5): харагдах тэмдгийн байршил (PLACEMENT_SPEC)

- Харагдах тэмдэг хуудасны агуулгатай давхцахгүй: `appearance.x/y` нь хүссэн байрлал; хуудсыг (текст, зураас, зураг,
  form XObject, annotation) скан хийж, давхцвал тогтсон дарааллаар (дээшээ 12 pt алхмаар, дараа нь эсрэг багана) эхний
  чөлөөтэй байрлал руу зөөнө. Үр дүн `placement` = `{ page, x, y, width, height, status }`, `status` ∈ `requested`
  (хүссэн газраа) · `moved` (зөөгдсөн) · `overlap` (чөлөөтэй газаргүй — хүссэн газраа агуулга дээр) · `unscanned`
  (хуудсыг скан хийж чадсангүй — хүссэн газраа). `overlap` / `unscanned` үед хэрэглэгчид мэдэгдэнэ; гарын үсэг хүчинтэй.
- Golden = Go reference `pades-golden-v5` (`placement/vectors.json` 29 vector, golden v5-ийн 6 шинэ тохиолдол).

## 0.3.0 — 2026-10-19 — Go reference v0.8.0 (golden v4): цуцлалтын нотолгоо, бүтцийн шалгалт, CA гинж, self-check, бүртгэл (BREAKING)

- `complete`: OCSP CertID = энэ гэрчилгээ + олгогч, CRL нь олгогчийнх (нэр, AKI = SKI, гарын үсэг), «good» нотолгоо
  шинэлэг (24 ц / ±5 мин). **Олгогчийн гарын үсэгтэй «revoked» (OCSP эсвэл CRL) → `LTV_UNAVAILABLE`,
  `certificateRevoked = true`, `retryable = false`** (өмнө нь revoked OCSP алгасагдаж цэвэр CRL-ээр амжилттай дуусдаг байв).
- `prepare` / `complete`: задлахаас өмнө давхарлалт > 256, ObjStm мөчлөг, `/Extends` > 64, `/Size` > 2^21 → `PDF_INVALID`
  (`complete` — `STATE_INVALID`); `/Encrypt <<` (шууд толь) → `PDF_ENCRYPTED`.
- Гинж: олгогч бүр CA (basicConstraints cA) ба keyCertSign; TSA гинжид pathLen ба EKU.
- `complete` гаралтаа шалгана (шинэ гарын үсэг = бэлдсэн, revision-оо хамарна, тоо = revIndex, /DSS) → эс бөгөөс
  `SELF_VALIDATION_FAILED`.
- Шинэ: `Completed.fileName`, `Completed.registration(...)` → `Registration` (CA `POST /pdf/signatures`-ийн бие, Go
  `pades.Registration`-тэй ижил). `priorCmsSha256` ба `priorRevisionSha256`-ийг зэрэг илгээхгүй (CA 400).
- Golden: Go `v0.8.0` (`golden/` + `golden/validate/` v4 оролт).

## 0.2.0 — 2026-10-15 — Go reference golden v3: харагдах гарын үсэг, priorRevisionSha256

- `PrepareOptions.appearance` (`SignatureAppearance`: page, x, y, width, height, lang): сонгосон хуудсанд харагдах
  widget (/F 4, /Annots-д нэмнэ), /AP /N форм XObject нь verify хуудасны фонт ба өөрийн QR
  (`https://ca.eidmongolia.mn/verify/<docId>/<revIndex>`); /Rotate-ийг content cm-ээр. Алга = үл харагдах, golden v2-той
  байт ижил. Go `core/appearance.go`-ийн 1:1 порт (APPEARANCE_SPEC.md).
- `Completed.priorRevisionSha256`: өмнөх гарын үсэг бүрийн `sha256(doc[0 : ByteRange төгсгөл])`, `priorCmsSha256`-тай
  ижил дарааллаар.
- Golden = Go reference `pades-golden-v3` (17 кейс, 5 нь харагдах).

## 0.1.0 — 2026-10-14

- Анхны нийтлэл: `GeregeEIDPades` (profile `pades-client/1`) — client-side PAdES `prepare` / `complete`,
  баталгаажуулалтын (QR) хуудас, RFC 3161 + OCSP/CRL + DSS. Golden vector = Go reference `pades-golden-v2`.
