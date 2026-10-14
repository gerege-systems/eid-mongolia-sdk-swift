# pades golden vectors (pades-client/1)

Native SDK бүр (TS, Swift, Kotlin, C#) энэ хавтсыг хуулж (sync скрипт + CI-д Go репогийн tag-тай тулгах) Go
reference-тэй **ижил байт** гаргаж байгааг шалгана — prepare (digest, DTBS, preparedSha256, byteRange) ба complete
(outSha256, бүтэн гаралт `output/<case>.pdf`). Үнэний эх сурвалж = энэ хавтас (CA репогийн `testdata/pades-client/` нь хуулбар).

> **`pki/*.pem` нь ЗӨВХӨН ТЕСТИЙН гэрчилгээ; `pki/*.key.pem` нь ТЕСТИЙН хувийн түлхүүр** (зөвхөн Go `-update`-д; native
> SDK-ууд хуулах шаардлагагүй — иргэний гарын үсэг `expect.signature`-д бэлэн) (root → 02 → 03 → 04 → иргэн/TSA, RSA-2048, `TEST ONLY …`
> нэртэй). Бодит гинжид итгэгдэхгүй; тестээс өөр зориулалтаар бүү ашигла. `desktop/pki/*.key` — мөн адил.

- `manifest.json` — тохиолдол бүр: `input` (эсвэл `case:<нэр>` — өмнөх тохиолдлын гаралт), `prepare` options
  (signerCert = `pki/citizen.pem`, chain = 04/03/02, roots = `pki/root.pem`, signingTime = `signingTime` нэмэгдэнэ),
  `expect` — `digest`, `dtbs`, `signedAttrs` (hex), `signature` (hex — complete-д өгөх иргэний гарын үсэг),
  `preparedSha256`, `byteRange`, `outSha256`, `cmsSha256`, `sigRevSha256`, `pageSha256`, `revIndex`, `docId`,
  `priorCmsSha256` эсвэл `error` (код). `output/<case>.pdf` — complete-ийн бүтэн гаралт.
- `signature` = `pki/citizen.key.pem`-ээр DTBS дээр RSA PKCS#1 v1.5 (тодорхойлогдсон).
- `complete`: TSA = `http://tsa.pki.test/`, OCSP/CRL = гэрчилгээний AIA/CDP (`*.pki.test`) — сүлжээгүй: HTTP хариуг
  `http/*.der`-ээс `manifest.http["METHOD URL hex(sha256(body))[:16]"]`-ээр өгнө (хүсэлтийн байт — WIRE.md). TSA nonce
  = WIRE.md §4, цаг = `now`; signingTime = manifest `signingTime` (+08:00).
- `input/` — CA-ийн Quartz PDF 1.3 (`quartz-pdf13.pdf`), qpdf `--object-streams=generate` ба `--linearize` хувилбар,
  `encrypted.pdf` (AES-256), CA-ийн хуучин stamp (`stamped.pdf` → `PDF_FOREIGN_SIGNATURE`), desktop-ийн objstm.
  `quartz-pdf13-second` — эхний гаралтын DSS revision дээр 2 дахь гарын үсэг (docID хуудаснаас, onBehalfOf).
- `desktop/` — eid-desktop-ийн Swift port-ын хуучин (CA профайл, xref FlateDecode) гаралт; Go core-ийг xref stream-ийн
  өгөгдлийг задалж тулгана (`pades/internal/core/desktop_golden_test.go`).

Шинэчлэх (профайл өөрчлөгдөхөд л): `go test ./pades -run Golden -update` — TSA token шинээр гарна (manifest, `http/`,
`output/` бүхэлдээ шинэчлэгдэнэ), дараа нь `ProfileVersion`-ийг нэмнэ. Runtime-д шахалт байхгүй тул golden нь Go-ийн
хувилбараас хамаарахгүй (1.25, 1.27-д шалгасан).
