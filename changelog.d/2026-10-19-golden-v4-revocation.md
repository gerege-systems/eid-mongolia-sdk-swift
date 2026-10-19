### 0.3.0 — Go reference v0.8.0 (golden v4): цуцлалтын нотолгоо, бүтцийн шалгалт, CA гинж, self-check, бүртгэл (BREAKING)

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
