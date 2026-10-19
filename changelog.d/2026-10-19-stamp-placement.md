### 0.4.0 — Go reference v0.11.0 (golden v5): харагдах тэмдгийн байршил (PLACEMENT_SPEC)

- Харагдах тэмдэг хуудасны агуулгатай давхцахгүй: `appearance.x/y` нь хүссэн байрлал; хуудсыг (текст, зураас, зураг,
  form XObject, annotation) скан хийж, давхцвал тогтсон дарааллаар (дээшээ 12 pt алхмаар, дараа нь эсрэг багана) эхний
  чөлөөтэй байрлал руу зөөнө. Үр дүн `placement` = `{ page, x, y, width, height, status }`, `status` ∈ `requested`
  (хүссэн газраа) · `moved` (зөөгдсөн) · `overlap` (чөлөөтэй газаргүй — хүссэн газраа агуулга дээр) · `unscanned`
  (хуудсыг скан хийж чадсангүй — хүссэн газраа). `overlap` / `unscanned` үед хэрэглэгчид мэдэгдэнэ; гарын үсэг хүчинтэй.
- Golden = Go reference `pades-golden-v5` (`placement/vectors.json` 29 vector, golden v5-ийн 6 шинэ тохиолдол).
