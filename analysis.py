"""
analysis.py
-----------
محرّك التحليل الأساسي: يأخذ بلاغ فحص أمني خام (HTTP headers ناقصة،
إعداد خاطئ، ثغرة معروفة...) ويستخدم الـ LLM (عبر llm_providers) مع
السياق التاريخي (عبر memory.py) لإصدار:
  1) قرار: هل هو بلاغ حقيقي أم False Positive؟ + درجة ثقة.
  2) شرح مبسّط للمخاطر (business impact).
  3) كود إصلاح جاهز (remediation code) قابل للتطبيق مباشرة، مع تحديد
     نوعه (diff/full_file) ولغته — لتسهيل تطبيقه لاحقاً في GitHub أو
     عرضه بشكل صحيح في التقرير النهائي.

تحديث Production-Ready:
  - REMEDIATION_HINTS: قاموس تلميحات خاص بأكثر أنواع الثغرات شيوعاً،
    يُحقن في الـ prompt كسياق إضافي (domain knowledge) بدل الاعتماد
    الكامل على معرفة النموذج العامة — يرفع جودة واتساق كود الإصلاح.
  - الاستجابة أصبحت تتضمن "language" و"patch_type" لمعرفة كيف يُطبَّق
    الإصلاح (Unified Diff جاهز للـ git apply، أو محتوى ملف كامل).
  - تحقق أكثر صرامة من شكل استجابة النموذج مع رسائل خطأ أوضح.
"""

from __future__ import annotations
import json
import logging
from dataclasses import dataclass
from typing import Optional

from llm_providers import LLMRouter
from memory import AgentMemory, Finding

logger = logging.getLogger("devsecops_agent.analysis")

# ---------------------------------------------------------------------
# تلميحات إصلاح خاصة بأكثر أنواع الثغرات شيوعاً في بيئات DevSecOps.
# الهدف: توجيه النموذج نحو صيغة إصلاح دقيقة ومتوافقة مع أدوات فعلية
# (nginx directives صحيحة، Dockerfile best-practices رسمية...) بدل
# ترك الأمر لحدس النموذج وحده. أضِف أي rule_id جديد يتكرر في مشروعك هنا.
# المطابقة substring-based على rule_id (case-insensitive) لتغطية أشكال
# تسمية مختلفة لنفس الفاحص.
# ---------------------------------------------------------------------
REMEDIATION_HINTS: dict[str, str] = {
    "CSP": (
        "لملفات nginx: استخدم `add_header Content-Security-Policy \"...\" always;` "
        "داخل بلوك server أو location. اقترح سياسة متحفّظة تبدأ بـ default-src 'self' "
        "ثم وسّعها حسب الحاجة الظاهرة في السياق. أعد المقتطف كـ Unified Diff إن أمكن."
    ),
    "HSTS": (
        "أضف `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;` "
        "وتأكد أن الموقع يعمل بالكامل عبر HTTPS قبل تفعيل includeSubDomains."
    ),
    "DOCKER_ROOT_USER": (
        "أضف مستخدم غير root في الـ Dockerfile: `RUN adduser --disabled-password --gecos '' appuser` "
        "ثم `USER appuser` قبل CMD/ENTRYPOINT. تأكد أن الملفات المطلوبة تملكها appuser عبر chown."
    ),
    "DOCKER": (
        "اتبع Docker best-practices: pin نسخة الصورة الأساسية (لا تستخدم latest)، "
        "لا تُدرج أسراراً (secrets) كـ ENV ثابتة، واستخدم multi-stage build إن أمكن."
    ),
    "X_FRAME_OPTIONS": (
        "أضف `add_header X-Frame-Options \"SAMEORIGIN\" always;` لمنع clickjacking."
    ),
    "X_CONTENT_TYPE": (
        "أضف `add_header X-Content-Type-Options \"nosniff\" always;`."
    ),
    "TLS": (
        "عطّل بروتوكولات TLS القديمة (`ssl_protocols TLSv1.2 TLSv1.3;`) وقيّد الـ cipher "
        "suites لمجموعة حديثة وآمنة فقط."
    ),
    "SQL_INJECTION": (
        "استبدل أي تركيب استعلام بـ string concatenation بـ parameterized queries / "
        "prepared statements حسب لغة/مكتبة الوصول لقاعدة البيانات الظاهرة في السياق."
    ),
    "HARDCODED_SECRET": (
        "انقل القيمة إلى متغير بيئة أو secret manager (مثل GitHub Actions secrets أو "
        "Vault)، واستبدلها في الكود بقراءة من `os.environ`، مع إضافة الملف/النمط إلى "
        ".gitignore إذا كان ملف إعداد محلي."
    ),
    # --- تلميحات خاصة بسكانر RCE / حقن الأكواد (scanners/rce_scanner.py) ---
    "EVAL": (
        "استبدل eval() بحل آمن ومحدود الصلاحية حسب الحاجة الفعلية: "
        "ast.literal_eval() إن كان الهدف تقييم قيم Python بسيطة (أرقام/قوائم/"
        "قواميس) فقط، أو قاموس تفويض (dispatch dict) صريح لمجموعة عمليات "
        "معروفة مسبقاً بدل تنفيذ أي نص وارد. لا تُنفّذ أي مدخل من المستخدم "
        "كنص برمجي مباشرة تحت أي ظرف."
    ),
    "EXEC": (
        "استبدل exec() بنفس منطق eval() أعلاه: قاموس تفويض لعمليات محددة "
        "مسبقاً، أو إعادة هيكلة المنطق كدوال عادية تُستدعى مباشرة بدل توليد "
        "كود Python وتنفيذه ديناميكياً من مدخل خارجي."
    ),
    "OS_SYSTEM": (
        "استبدل os.system() بـ subprocess.run([...], shell=False) مع تمرير "
        "الأمر ووسائطه كقائمة عناصر منفصلة (وليس سلسلة نصية واحدة مُركَّبة)، "
        "بحيث لا يمر أي جزء من مدخل المستخدم عبر مفسّر الشل. تحقق أيضاً من "
        "صحة/قائمة بيضاء للمدخلات (مثل اسم ملف أو رقم) قبل استخدامها كوسيط."
    ),
    "SHELL": (
        "أزل shell=True من استدعاء subprocess واستبدله بقائمة أوامر صريحة، "
        "مثل: subprocess.run(['ping', '-c', '1', host], shell=False). إن كان "
        "لا بد من استخدام الشل فعلياً، استخدم shlex.quote() على كل جزء متغير "
        "من الأمر كحد أدنى، مع التحقق الصارم من صحة المدخل أولاً."
    ),
    "PICKLE": (
        "لا تُلغِ تسلسل بيانات من مصدر غير موثوق عبر pickle.load()/loads() "
        "إطلاقاً — استبدله بـ json (json.load/loads) لو كانت البيانات هيكلية "
        "بسيطة. إن كان pickle ضرورياً لأسباب توافق، وقّع البيانات (HMAC) عند "
        "الحفظ وتحقق من التوقيع قبل فك التسلسل، أو استخدم بديلاً آمناً مثل "
        "المكتبة hmac + json بدل pickle الخام."
    ),
}


def _find_hint(rule_id: str) -> str:
    rid = rule_id.upper()
    for key, hint in REMEDIATION_HINTS.items():
        if key in rid:
            return hint
    return "لا يوجد تلميح مخصص لهذا النوع — اعتمد على أفضل الممارسات القياسية المعروفة لهذا النوع من الثغرات."


SYSTEM_PROMPT = """أنت محلل أمن سيبراني وDevSecOps خبير، متخصص في كتابة إصلاحات كود قابلة
للتطبيق مباشرة (production-ready)، وليس شرحاً نظرياً فقط.

أعد الإجابة بصيغة JSON فقط دون أي نص إضافي أو Markdown، بالمفاتيح التالية بالضبط:
{
  "is_false_positive": true|false,
  "confidence": 0.0-1.0,
  "risk_level": "critical|high|medium|low",
  "business_impact": "شرح مختصر بالعربية للأثر على العمل/المتجر",
  "remediation_explanation": "شرح خطوات الإصلاح خطوة بخطوة",
  "remediation_code": "كود الإصلاح الفعلي، جاهز للتطبيق",
  "patch_type": "diff" أو "full_file",
  "language": "لغة/نوع الملف المتأثر، مثل: nginx, dockerfile, python, yaml, javascript"
}

قواعد إلزامية لحقل remediation_code:
- إن كان الإصلاح تعديلاً صغيراً على ملف موجود (سطر/بضعة أسطر)، أعده بصيغة
  Unified Diff قياسية (سطور تبدأ بـ --- / +++ / @@) بحيث يمكن تطبيقه مباشرة
  عبر `git apply`، وضع "patch_type": "diff".
- إن كان الملف صغيراً أو الإصلاح يطال بنيته بالكامل، أعد محتوى الملف كاملاً
  بعد الإصلاح، وضع "patch_type": "full_file".
- لا تُدرج أي شرح نصي داخل remediation_code نفسه — الشرح مكانه
  remediation_explanation فقط.
- إن لم يكن هناك ثغرة حقيقية (is_false_positive = true)، اترك remediation_code
  فارغاً "".

استخدم "دليل الإصلاح الخاص بهذا النوع من الثغرات" المُرفق أدناه ضمن رسالة
المستخدم كمرجع تقني لصياغة الحل بدقة أعلى.

استخدم أي سياق تاريخي مُرفق (قرارات بشرية سابقة على بلاغات مشابهة) لتحسين
دقة قرارك بخصوص False Positive، وامنح الأولوية لثقة الفريق البشري إن تعارضت
مع حدسك."""


@dataclass
class AnalysisResult:
    is_false_positive: bool
    confidence: float
    risk_level: str
    business_impact: str
    remediation_explanation: str
    remediation_code: str
    patch_type: Optional[str] = None
    language: Optional[str] = None


class SecurityAnalyzer:
    def __init__(self, router: LLMRouter, memory: AgentMemory):
        self.router = router
        self.memory = memory

    def analyze_finding(self, scan_id: int, rule_id: str, target: str,
                         severity: str, description: str, raw_context: str = "") -> tuple[AnalysisResult, int]:
        prior = self.memory.get_prior_context(rule_id, target)
        hint = _find_hint(rule_id)

        user_prompt = json.dumps({
            "rule_id": rule_id,
            "target": target,
            "severity": severity,
            "description": description,
            "raw_scanner_context": raw_context,
            "remediation_guide_for_this_rule_type": hint,
            "prior_human_decisions_on_similar_findings": prior,
        }, ensure_ascii=False, indent=2)

        # حجم أكبر لأن كود الإصلاح (خصوصاً full_file) قد يكون طويلاً
        response = self.router.complete(SYSTEM_PROMPT, user_prompt, max_tokens=2500)

        try:
            parsed = json.loads(_strip_code_fences(response.text))
            required = ["is_false_positive", "confidence", "risk_level",
                        "business_impact", "remediation_explanation"]
            missing = [k for k in required if k not in parsed]
            if missing:
                raise KeyError(f"مفاتيح ناقصة في استجابة النموذج: {missing}")

            patch_type = parsed.get("patch_type")
            if patch_type not in (None, "diff", "full_file"):
                logger.warning("قيمة patch_type غير متوقعة: %s — تُعامل كـ full_file", patch_type)
                patch_type = "full_file"

            result = AnalysisResult(
                is_false_positive=bool(parsed["is_false_positive"]),
                confidence=float(parsed["confidence"]),
                risk_level=parsed["risk_level"],
                business_impact=parsed["business_impact"],
                remediation_explanation=parsed["remediation_explanation"],
                remediation_code=parsed.get("remediation_code", "") or "",
                patch_type=patch_type,
                language=parsed.get("language"),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error("فشل تحليل استجابة النموذج (%s): %s", e, response.text[:300])
            raise

        finding = Finding(
            rule_id=rule_id,
            target=target,
            severity=severity,
            description=description,
            llm_verdict="false_positive" if result.is_false_positive else "confirmed",
            llm_confidence=result.confidence,
            remediation_code=result.remediation_code,
            patch_type=result.patch_type,
            language=result.language,
        )
        finding_id = self.memory.add_finding(scan_id, finding)
        return result, finding_id


def _strip_code_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()
