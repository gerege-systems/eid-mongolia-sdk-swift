"""Golden гаралт бүрийг pyHanko-оор бие даан шалгана (Go validator-оос хамааралгүй гадны шалгагч).

Гарын үсэг бүр: INTACT (криптограф), VALID + TRUSTED (тестийн root), LT — цуцлалтын мэдээлэл ЗӨВХӨН баримтын /DSS-ээс
(allow_fetching=False, hard-fail, цаг = manifest `now`), timestamp хүчинтэй, өөрчлөлт нь зөвхөн гарын үсэг/форм бөглөлт. Харагдах эсэх (widget /Rect хоосон биш) manifest-ийн `prepare.appearance`-тэй
таарна. Ашиглалт: python pyhanko_check.py <golden хавтас>
"""
import json
import sys
from pathlib import Path

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from datetime import datetime

from pyhanko.sign.validation import DocumentSecurityStore, validate_pdf_signature
from pyhanko.sign.validation.settings import KeyUsageConstraints
from pyhanko.sign.validation.status import ModificationLevel

golden = Path(sys.argv[1])
manifest = json.loads((golden / "manifest.json").read_text())
root = load_cert_from_pemder(str(golden / "pki" / "root.pem"))
moment = datetime.fromisoformat(manifest["now"])
failed = 0
checked = 0
for case in manifest["cases"]:
    out = golden / "output" / (case["name"] + ".pdf")
    if case["expect"].get("error") or not out.exists():
        continue
    want_visible = bool(case["prepare"].get("appearance"))
    with out.open("rb") as f:
        r = PdfFileReader(f)
        sigs = r.embedded_signatures
        dss = DocumentSecurityStore.read_dss(r)

        def vc():
            return dss.as_validation_context(
                {"trust_roots": [root], "allow_fetching": False, "revocation_mode": "hard-fail", "moment": moment}
            )

        for i, sig in enumerate(sigs):
            st = validate_pdf_signature(
                sig,
                signer_validation_context=vc(),
                ts_validation_context=vc(),
                key_usage_settings=KeyUsageConstraints(key_usage=set()),
            )
            rect = [float(x) for x in sig.sig_field.get("/Rect", [0, 0, 0, 0])]
            visible = rect[0] != rect[2] and rect[1] != rect[3]
            # Харагдах нь зөвхөн тухайн тохиолдлын шинэ (сүүлийн) гарын үсэг.
            expect_vis = want_visible if i == len(sigs) - 1 else None
            ts = st.timestamp_validity
            ok = st.intact and st.valid and st.trusted and ts is not None and ts.intact and ts.valid and ts.trusted
            ok = ok and st.modification_level in (ModificationLevel.NONE, ModificationLevel.LTA_UPDATES, ModificationLevel.FORM_FILLING)
            ok = ok and (expect_vis is None or visible == expect_vis)
            level = st.modification_level.name if st.modification_level else "?"
            print(f"{case['name']:32} sig{i + 1} intact={st.intact} valid={st.valid} trusted={st.trusted} "
                  f"ts={bool(ts and ts.trusted)} mod={level} visible={visible} {'OK' if ok else 'FAIL'}")
            checked += 1
            failed += 0 if ok else 1
print(f"{checked} signatures, {failed} failed")
sys.exit(1 if failed or not checked else 0)
