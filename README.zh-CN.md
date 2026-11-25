[Монгол](README.md) · [English](README.en.md) · 中文

# eID Mongolia — PAdES SDK (Swift)

`GeregeEIDPades` — eID Mongolia **客户端 PAdES**（PDF 签名）的 Swift 库。PDF 绝不会发送到 eID 服务器：
应用在本地准备 PDF（`prepare`），只让公民的手机或 USB 令牌对 32 字节的 DTBS 签名，
再把签名嵌入 PDF（`complete`：RFC 3161 时间戳 + OCSP/CRL + DSS → PAdES B-LT）。

- iOS 14+ / macOS 13+（可在 Mac App Store 沙盒中运行）
- 无第三方依赖——CryptoKit、Security.framework、系统 zlib
- 配置文件 `pades-client/1`——与 Go 参考实现（[`eid-mongolia-sdk-go`](https://github.com/gerege-systems/eid-mongolia-sdk-go)
  的 `pades`）**字节级完全一致**的输出（CI 通过 golden vector 校验）
- Android 版本：[`eid-mongolia-sdk-android`](https://github.com/gerege-systems/eid-mongolia-sdk-android)——API 一一对应

## 安装（Swift Package Manager）

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

版本：使用最新的 tag（[releases](https://github.com/gerege-systems/eid-mongolia-sdk-swift/tags)）。

Xcode：**File → Add Package Dependencies…** → `https://github.com/gerege-systems/eid-mongolia-sdk-swift.git`。

## 用法

```swift
import GeregeEIDPades

// 1) 无需网络：准备 PDF 并生成 DTBS
// verifyPage: true 时必须提供 fileName（否则 REQUEST_INVALID）；CA 仅在带验证页时才登记第一个 eID 签名
let prepared = try EidPades.prepare(pdf: pdf, options: .init(signerCert: signCertDER, verifyPage: true,
                                                             fileName: "合同1号.pdf"))
// prepared.state 可以保存；让手机/令牌对 prepared.dtbs（32 字节）签名

// 2) TSA + OCSP/CRL + DSS
let done = try await EidPades.complete(state: prepared.state, signature: sig)
// done.pdf, done.cms, done.docId, done.outSha256, done.inSha256, done.hasPage, done.pageSha256,
// done.revIndex, done.sigRevSha256, done.priorCmsSha256, done.priorRevisionSha256, done.signerCert, done.fileName,
// done.claimedRole
let body = try JSONEncoder().encode(done.registration(medium: .phone, sessionId: sessionID))
// 省略 medium 时由 sessionId 推断：有则 .phone，否则 .token（CA 的配对规则）。.phone 但没有 sessionId、
// .token 但带有 sessionId，或带 claimedRole 的 prepare 却没有 onBehalfOf → REQUEST_INVALID（不会发往 CA）。
// → RP 后端将 body 原样登记到 eID（POST /pdf/signatures）
```

- `prepare`：预检查（加密、DocMDP P=1、先前的签名、≤ 16 个）；对第一个 eID 签名，若
  `verifyPage: true`，则生成验证（QR）页（`lang`：`mn` 默认 / `en`；NotoSans 子集字体，OFL——
  `Sources/GeregeEIDPades/Resources/fonts/OFL.txt`）、签名 revision、signedAttrs（+ `claimedRole`）→ DTBS。
  `verifyPagePosition: "first"`（0.8.0+）——该页成为文档的第 1 页（默认 `"last"`）；`appearance.page`、
  `suggestPlacement`、`placement.page` 按输入 PDF 的页码计数（`PAGE_SPEC.md` §8a、`PLACEMENT_SPEC.md` §1b）。
- `complete`：对 DTBS 验证公民的签名（RSA PKCS#1 v1.5、ECDSA）→ RFC 3161 → CMS → 嵌入 →
  OCSP/CRL → DSS revision。
- **可见签名**（可选，Go 的 `APPEARANCE_SPEC.md`）：`PrepareOptions.appearance = .init(page: 0, x: 36, y: 36,
  width: 220, height: 64)`——单位 pt，从页面可见区域（`/Rotate` 之后）的左下角起算；`page` 0 = 输入中**不是** eID
  验证页的最后一页（跳过先前签名的验证页；`PLACEMENT_SPEC.md` §1a），
  1… 则保持明确的页码。高度 ≥ 45 pt；若超出页面或文字放不下，则 `REQUEST_INVALID`。nil = 不可见。
- **签章位置**（Go 的 `PLACEMENT_SPEC.md`）：`x/y` 是请求的位置——若与页面内容重叠（保留 4 pt 间距），
  则移到第一个空闲位置（同一高度的镜像列 → 在请求的列中上移 12 pt → 在镜像列中上移）。
  `prepared.placement`（`page`、`x`、`y`、`width`、`height`——pt；`status`：`.requested` | `.moved` | `.overlap`——没有空闲
  位置，放在请求的位置 | `.unscanned`——页面无法在限制内读完，放在请求的位置）。建议将 `.overlap` /
  `.unscanned` 告知用户——无论哪种情况，签名都有效。
- **公民自行摆放**（`PLACEMENT_SPEC.md` §6a/§6b）：`EidPades.suggestPlacement(pdf:appearance:)`——在没有签名、
  证书和网络的情况下运行 `prepare` 的定位算法 → `PlacementSuggestion`（`page`、`x`、`y`、
  `width`、`height`、`status` = 相同输入下的 `prepared.placement`；`pageWidth`、`pageHeight`、`pageCount`、`pages[]`
  （每页的可见尺寸，pt；无法读取则为 0×0））。UI 在预览中显示默认位置，并通过 `SignatureAppearance(…, exact: true)` 传入
  公民拖动后的位置：签章会精确绘制在那里，绝不会移动
  （`status`：`.requested`，或其下有内容时为 `.overlap`，以及 `.unscanned`；绝不会是 `.moved`）；若超出页面则
  `REQUEST_INVALID`。屏幕（左上，`s` px/pt）↔ appearance：`left = x·s`，`top = (pageHeight − y − height)·s`；
  反向 `x = left/s`，`y = pageHeight − top/s − height`。`exact: false`（默认）与之前字节级一致。
- `registration(medium:sessionId:onBehalfOf:)`——先前的签名仅通过 `priorCmsSha256` 发送（若同时发送两个列表，
  CA 返回 400）。遇到 409 `PRIOR_MISMATCH` 时，把 `priorSignatures` 中匹配的项移到 `priorRevisionSha256` 后
  重新发送（在 CA 端组装，模式 A）。以下情况返回 `REQUEST_INVALID`：revIndex 为 1 但没有页面、没有 `fileName`、`medium` ↔ `sessionId` 冲突（phone 必须有 sessionId，token 不能
  有；省略 `medium` 则由 sessionId 推断），或带 `claimedRole` 的 prepare 其 `onBehalfOf`（NTRMN-…）为空。
- 结构检查（Go 的 `PRECHECKS.md` #2a/#2b）：嵌套 > 256、ObjStm 循环、`/Extends` > 64、`/Size` > 2^21 →
  `PDF_INVALID`（在 `complete` 中为 `STATE_INVALID`）。
- `CompleteOptions.transport`——自定义 HTTP（代理、沙盒）；默认使用 URLSession（总期限 10 秒，不跟随重定向，≤ 4 MiB）。
- 错误：`EidPadesError.code`——所有 SDK 中一致的稳定错误码（`PDF_INVALID`、`PDF_ENCRYPTED`、`PDF_LOCKED`、
  `PDF_FOREIGN_SIGNATURE`、`SIGNATURE_INVALID`、`TSA_UNAVAILABLE`、`LTV_UNAVAILABLE`、`STATE_INVALID`、…）。
  `retryable`——TSA/LTV 的暂时性错误（用相同的 state 重试）；`certificateRevoked`——证书链中的证书已被其颁发者签名的
  OCSP/CRL 吊销（`LTV_UNAVAILABLE`，终态——`retryable = false`）。
- 本库不含完整的 validator——验证在后端使用 Go SDK 完成。

集成文档：<https://developer.eidmongolia.mn>。

## 一致性（Conformance）

`Tests/GeregeEIDPadesTests/golden/`——Go 参考实现的 golden vector（输入 PDF、**仅用于测试的** PKI 证书、
固定的 TSA/OCSP/CRL 响应）；私钥已移除。来源 tag 位于 `golden/SOURCE`。

```sh
scripts/sync-pades-golden.sh --check   # vendored = Go 仓库的 tag
swift test
```

## 来源与贡献

本仓库是 eID Mongolia 内部仓库的**镜像**（`sync from ca <sha>` 提交）。缺陷和建议请提交到
GitHub Issues；PR 会转到内部仓库后再合入。

## 许可证

MIT——[LICENSE](LICENSE)。字体：SIL Open Font License 1.1（`Sources/GeregeEIDPades/Resources/fonts/OFL.txt`）。
