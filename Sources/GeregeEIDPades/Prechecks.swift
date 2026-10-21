import Foundation

/// "Light" pre-checks before signing — exactly the Go reference `pades/PRECHECKS.md` (pades-client/1), in its order.
/// No chain/revocation/timestamp-trust checks here (that is the Go validator's job).
enum Prechecks {
    static let verifyURLPrefix = "https://ca.eidmongolia.mn/verify/"

    /// PRECHECKS.md #4–#10. (newDoc, revIndex): unsigned → (true, 1); signed and acceptable → (false, signatures + 1).
    /// `issuers` = eID issuing CAs (04, 05) + the current signer's issuer (chain[0]).
    static func inspect(_ doc: [UInt8], issuers: [X509Cert]) throws -> (Bool, Int) {
        let (r, root, sigs) = try open(doc)
        if sigs.isEmpty { return (true, 1) }
        guard sigs.count < EidPades.maxSignatures else {                                                     // #7
            throw EidPadesError(code: .pdfTooManySignatures, message: "too many signatures")
        }
        var parsed: [PriorSignature] = []
        for d in sigs {                                                                                      // #8
            guard let p = PriorSignature(d, reader: r, doc: doc) else {
                throw EidPadesError(code: .pdfPriorSignatureInvalid, message: "prior signature is invalid")
            }
            parsed.append(p)
        }
        var locked = docMDPP1(r, (try? r.resolve(root["Perms"]))?.dict.flatMap { try? r.resolve($0["DocMDP"]) }?.dict)
        for d in sigs where docMDPP1(r, d) { locked = true }
        if locked { throw EidPadesError(code: .pdfLocked, message: "document is certified with DocMDP P=1") }   // #9
        let hasDSS = (try? r.resolve(root["DSS"]))?.dict != nil
        for p in parsed where !(p.subFilter == "ETSI.CAdES.detached" && p.hasTimestamp && hasDSS &&             // #10
                                issuers.contains(where: { p.signer.isSigned(by: $0) })) {
            throw EidPadesError(code: .pdfForeignSignature, message: "document has a signature that is not an eID B-LT signature")
        }
        return (false, sigs.count + 1)
    }

    /// PRECHECKS.md #4–#6 (Go `encrypted` + `scanSignatures`): the reader, the Catalog and the signature dictionaries.
    /// Shared by `prepare` and `suggestPlacement`.
    static func open(_ doc: [UInt8]) throws -> (PdfReader, PdfDict, [PdfDict]) {
        let r: PdfReader
        do { r = try PdfReader(doc) } catch {
            if encryptedByScan(doc) { throw EidPadesError(code: .pdfEncrypted, message: "encrypted PDF") }  // #4
            throw EidPadesError(code: .pdfInvalid, message: "not a PDF or damaged: \(error)")              // #5
        }
        if !r.trailer["Encrypt"].isNull { throw EidPadesError(code: .pdfEncrypted, message: "encrypted PDF") }
        guard let root = (try? r.resolve(r.trailer["Root"]))?.dict else {
            throw EidPadesError(code: .pdfInvalid, message: "Catalog missing")
        }
        return (r, root, signatureDicts(r))                                                                  // #6
    }

    /// A /Reference entry (/TransformMethod /DocMDP or absent) with /TransformParams /P 1.
    static func docMDPP1(_ r: PdfReader, _ sig: PdfDict?) -> Bool {
        guard let sig, let refs = (try? r.resolve(sig["Reference"]))?.array else { return false }
        for e in refs {
            guard let d = (try? r.resolve(e))?.dict else { continue }
            let m = (try? r.resolve(d["TransformMethod"])) ?? .null
            guard m.isNull || m.nameValue == "DocMDP",
                  let tp = (try? r.resolve(d["TransformParams"]))?.dict,
                  case .int(1) = (try? r.resolve(tp["P"])) ?? .null else { continue }
            return true
        }
        return false
    }

    /// Objects with /ByteRange and /Contents (Go `vpage.HasSignatureObjects`), in object-number order.
    static func signatureDicts(_ r: PdfReader) -> [PdfDict] {
        var out: [PdfDict] = []
        for id in r.xref.keys.sorted() {
            let gen: Int
            if case .offset(_, let g) = r.xref[id]! { gen = g } else { gen = 0 }
            guard let d = (try? r.object(PdfRef(id: id, gen: gen)))?.dict else { continue }
            if !d["ByteRange"].isNull, !d["Contents"].isNull { out.append(d) }
        }
        return out
    }

    /// CMS DER (first ASN.1 element of the hex /Contents) of every signature except the one at `excluding`,
    /// in object-number order (Go `validate.Extract` → `CMSSHA256`), with its revision end
    /// (ByteRange[2]+ByteRange[3] — Go `PriorRevisionSHA256` = sha256(doc[0:end])).
    static func priorSignatures(_ doc: [UInt8], excluding br: [Int]) -> [(cms: [UInt8], end: Int)] {
        guard let r = try? PdfReader(doc) else { return [] }
        var out: [(cms: [UInt8], end: Int)] = []
        for d in signatureDicts(r) {
            if let t = (try? r.resolve(d["Type"]))?.nameValue, t != "Sig" { continue }
            guard let arr = (try? r.resolve(d["ByteRange"]))?.array else { continue }
            let got = arr.compactMap { (try? r.resolve($0))?.intValue }.map(Int.init)
            if got == br { continue }
            if let der = PriorSignature.contentsDER(doc, got), got.count == 4, got[2] + got[3] <= doc.count {
                out.append((der, got[2] + got[3]))
            }
        }
        return out
    }

    /// /Encrypt reference or direct dictionary in the raw bytes (readers that cannot open AES-256 files) — PRECHECKS #4.
    static func encryptedByScan(_ doc: [UInt8]) -> Bool { Structure.hasEncryptRef(doc) }

    /// docId from the first eID signature's verification page (/Link /URI https://ca.eidmongolia.mn/verify/<uuid>).
    /// Objects in object-number order, each with the generation its xref entry records (PLACEMENT_SPEC §1a).
    static func docIDFromPage(_ doc: [UInt8], reader: PdfReader? = nil) -> String? {
        guard let r = reader ?? (try? PdfReader(doc)) else { return nil }
        for id in r.xref.keys.sorted() {
            let gen: Int
            if case .offset(_, let g) = r.xref[id]! { gen = g } else { gen = 0 }
            guard let d = (try? r.object(PdfRef(id: id, gen: gen)))?.dict,
                  (try? r.resolve(d["Subtype"]))?.nameValue == "Link",
                  let a = (try? r.resolve(d["A"]))?.dict, case .string(let u) = (try? r.resolve(a["URI"])) ?? .null else { continue }
            let s = String(decoding: u, as: UTF8.self)
            if s.hasPrefix(verifyURLPrefix), EidPades.isUUID(String(s.dropFirst(verifyURLPrefix.count))) {
                return String(s.dropFirst(verifyURLPrefix.count))
            }
        }
        return nil
    }
}

/// PRECHECKS #8: ByteRange [0 a b c] framing /Contents, the signed revision ends with %%EOF, the hex /Contents' first
/// ASN.1 SEQUENCE is a CMS SignedData with one SignerInfo whose messageDigest and signature verify.
struct PriorSignature {
    let signer: X509Cert
    let hasTimestamp: Bool
    let subFilter: String

    init?(_ d: PdfDict, reader r: PdfReader, doc: [UInt8]) {
        guard let arr = (try? r.resolve(d["ByteRange"]))?.array, arr.count == 4 else { return nil }
        var br: [Int] = []
        for e in arr {
            guard case .int(let v) = (try? r.resolve(e)) ?? .null else { return nil }
            br.append(Int(v))
        }
        let a = br[1], b = br[2], c = br[3]
        guard br[0] == 0, a > 0, b > a + 1, c >= 0, b + c <= doc.count, doc[a] == 0x3C, doc[b - 1] == 0x3E else { return nil }
        var end = b + c
        while end > 0, doc[end - 1] == 0x0A || doc[end - 1] == 0x0D { end -= 1 }
        guard end >= 5, Array(doc[(end - 5)..<end]) == Array("%%EOF".utf8) else { return nil }
        guard let der = Self.contentsDER(doc, br), let el = try? DER.parse(der), el.tag == 0x30,
              let ci = try? el.children(), ci.count == 2, ci[0].oid == OID.signedData,
              let sd = try? ci[1].child(0).children(), sd.count >= 4,
              let signerInfos = sd.last, signerInfos.tag == 0x31,
              let sis = try? signerInfos.children(), sis.count == 1,
              let si = try? sis[0].children(), si.count >= 6 else { return nil }
        var certs: [X509Cert] = []
        if let cs = sd.first(where: { $0.tag == 0xA0 }) {
            certs = ((try? cs.children()) ?? []).compactMap { try? X509Cert(der: $0.bytes) }
        }
        guard let ias = try? si[1].children(), ias.count == 2,
              let s = certs.first(where: { $0.rawIssuer == ias[0].bytes && DER.minimal($0.serial) == ias[1].unsignedInteger }),
              si[3].tag == 0xA0, let digestAlg = try? si[2].child(0).oid,
              let sigAlg = try? si[4].child(0).oid, let sig = try? si[5].expect(0x04).contents else { return nil }
        var md: [UInt8]?
        for at in (try? si[3].children()) ?? [] {
            if let q = try? at.children(), q.count == 2, q[0].oid == OID.messageDigest { md = try? q[1].child(0).contents }
        }
        var signed = [UInt8]()
        signed.reserveCapacity(a + c)
        signed += doc[0..<a]
        signed += doc[b..<(b + c)]
        guard let want = Crypto.digest(digestAlg, signed), md == want else { return nil }
        var setAttrs = si[3].bytes
        setAttrs[0] = 0x31
        let alg = sigAlg == OID.ecPublicKey ? Crypto.ecdsaAlgorithm(digest: digestAlg) : TSA.signatureAlgorithm(sigAlg, digest: digestAlg)
        guard Crypto.verify(alg: alg, key: s, data: setAttrs, signature: sig) else { return nil }
        signer = s
        var ts = false
        if si.count > 6, si[6].tag == 0xA1 {
            for at in (try? si[6].children()) ?? [] where (try? at.child(0).oid) == OID.timeStampToken { ts = true }
        }
        hasTimestamp = ts
        subFilter = (try? r.resolve(d["SubFilter"]))?.nameValue ?? ""
    }

    /// The hex /Contents framed by ByteRange [0 a b c], decoded; its first ASN.1 element (zero padding dropped).
    static func contentsDER(_ doc: [UInt8], _ br: [Int]) -> [UInt8]? {
        guard br.count == 4 else { return nil }
        let a = br[1], b = br[2]
        guard a > 0, b > a + 1, b <= doc.count, (b - a - 2) % 2 == 0 else { return nil }
        var raw = [UInt8]()
        raw.reserveCapacity((b - a - 2) / 2)
        var i = a + 1
        while i < b - 1 {
            guard let hi = PdfLexer.hexVal(doc[i]), let lo = PdfLexer.hexVal(doc[i + 1]) else { return nil }
            raw.append(hi << 4 | lo)
            i += 2
        }
        guard let el = try? DER.parse(raw[...]), el.tag == 0x30 else { return nil }
        return el.bytes
    }
}
