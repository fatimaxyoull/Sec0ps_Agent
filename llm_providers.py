"""
llm_providers.py
-----------------
طبقة موحّدة (Abstraction Layer) للتعامل مع أكثر من مزود ذكاء اصطناعي
(Groq / Gemini / Claude / OpenAI) عبر استدعاءات REST API مباشرة، بدون
الاعتماد على SDKs ثقيلة قد تتغيّر واجهاتها بسرعة. Groq وGemini يوفّران
مستوى مجانياً (Free Tier) يمكن استخدامه كبديل عملي لمزودات مدفوعة أثناء
مرحلة الـ MVP.

الفكرة: كل مزود يطبّق نفس الواجهة (LLMProvider) عبر دالة complete()
بحيث يمكن للـ Agent التبديل بينها بسهولة أو استخدام أكثر من واحد
كطبقات تحقق متقاطع (cross-validation) لتقليل الـ False Positives.

تحديث: تمت إضافة MockProvider سابقاً كخط دفاع أخير (local fallback)، لكنه
أصبح الآن **معطّلاً افتراضياً** (`use_mock_fallback=False`) بناءً على قرار
الاعتماد الكامل على Groq API الحقيقي لكل التحليل والتوصيات — أي فشل حقيقي
في المزود يُرفَع كخطأ واضح بدل تحليل وهمي صامت قد يُفهم خطأً كتحليل حقيقي.
الكلاس ما زال متوفراً ويمكن تفعيله صراحةً (اختبار محلي بدون إنترنت مثلاً)
عبر تمرير use_mock_fallback=True.

تحديث آخر (نظام تبديل ذكي بين مزودين فعليين — Groq + Gemini):
بدل إعادة محاولة نفس المزود عند 429 (النسخة السابقة)، أصبح أي خطأ 429
(rate limit) أو خطأ اتصال (timeout/انقطاع شبكة) يُرفَع فوراً بدون انتظار
أو محاولات متكررة على نفس المزود، بحيث يتحول LLMRouter.complete() مباشرة
إلى المزود التالي في self.order (مثلاً Gemini بعد فشل Groq) دون أي توقف
ملحوظ. هذا أسرع وأكثر منطقية من الانتظار على مزود محدود الحصة بينما يوجد
مزود بديل جاهز فوراً بمفتاح صالح.
"""

from __future__ import annotations
import os
import json
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger("devsecops_agent.llm")


def _read_key(env_var: str) -> Optional[str]:
    """
    قراءة آمنة لمفتاح API من متغيرات البيئة: تُرجع None إن كان غير
    معرَّف أو فارغاً أو مسافات بيضاء فقط (بدل اعتباره "موجوداً" خطأً
    بسبب خطأ نسخ شائع من ملف .env)، ولا تطبع قيمة المفتاح في أي مكان.
    """
    value = os.environ.get(env_var)
    if value is None:
        return None
    value = value.strip()
    return value or None


class RateLimitError(RuntimeError):
    """
    تُرفع فوراً عند استجابة 429 من أي مزود — بدون أي انتظار أو إعادة
    محاولة على نفس المزود. LLMRouter.complete() يلتقطها خصيصاً ويتحول
    مباشرة للمزود التالي في قائمة self.order، فيتحقق التبديل الذكي
    المطلوب بين Groq وGemini (أو أي مزودين آخرين) دون أي تأخير.
    """
    def __init__(self, provider_name: str, retry_after: Optional[str] = None):
        self.provider_name = provider_name
        self.retry_after = retry_after
        msg = f"{provider_name}: تم تجاوز حد الطلبات (429 rate limit)"
        if retry_after:
            msg += f" — المزود يقترح الانتظار {retry_after} ثانية قبل محاولته مجدداً لاحقاً"
        super().__init__(msg)


@dataclass
class LLMResponse:
    provider: str
    model: str
    text: str
    raw: dict
    latency_ms: int
    is_fallback: bool = False  # True إذا جاءت من MockProvider


class LLMProvider(ABC):
    """واجهة موحّدة يجب أن يطبّقها أي مزود ذكاء اصطناعي."""

    name: str = "base"

    @abstractmethod
    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        ...

    def _timed_post(self, url: str, headers: dict, payload: dict, timeout: int = 60) -> tuple[dict, int]:
        """
        ينفّذ POST مع قياس الزمن. عند 429 يرفع RateLimitError فوراً (بدون
        انتظار محلي) ليتولى LLMRouter التبديل الفوري لمزود آخر. أي خطأ
        اتصال (Timeout/ConnectionError) يُترك يصعد كما هو من requests —
        LLMRouter.complete() يلتقطه أيضاً ويبدّل المزود بنفس الآلية.
        """
        start = time.time()
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code == 429:
            raise RateLimitError(self.name, retry_after=resp.headers.get("Retry-After"))

        if resp.status_code >= 400:
            logger.error("%s API error %s: %s", self.name, resp.status_code, resp.text[:500])
            resp.raise_for_status()

        return resp.json(), latency_ms


class ClaudeProvider(LLMProvider):
    name = "claude"

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-6"):
        self.api_key = api_key or os.environ["ANTHROPIC_API_KEY"]
        self.model = model
        self.url = "https://api.anthropic.com/v1/messages"

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        data, latency = self._timed_post(self.url, headers, payload)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return LLMResponse(self.name, self.model, text, data, latency)


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4.1"):
        self.api_key = api_key or os.environ["OPENAI_API_KEY"]
        self.model = model
        self.url = "https://api.openai.com/v1/chat/completions"

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        data, latency = self._timed_post(self.url, headers, payload)
        text = data["choices"][0]["message"]["content"]
        return LLMResponse(self.name, self.model, text, data, latency)


class GroqProvider(LLMProvider):
    """
    Groq يوفّر استدلالاً سريعاً ومجانياً (ضمن حدود معقولة) لنماذج مفتوحة
    مثل Llama و DeepSeek، بواجهة متوافقة مع OpenAI Chat Completions —
    لذا شكل الطلب/الاستجابة مطابق تقريباً لـ OpenAIProvider أعلاه.

    التسجيل والحصول على مفتاح مجاني: https://console.groq.com
    النماذج المدعومة الشائعة (تُحدَّث دورياً من طرف Groq، تحقق من
    https://console.groq.com/docs/models لأحدث قائمة):
      - "llama-3.3-70b-versatile"        (افتراضي: توازن جيد بين الجودة والسرعة)
      - "deepseek-r1-distill-llama-70b"  (نموذج استدلال/reasoning أعمق، أبطأ قليلاً)
    """

    name = "groq"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ["GROQ_API_KEY"]
        self.model = model or os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        try:
            data, latency = self._timed_post(self.url, headers, payload)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                # ملاحظة: لا يقوم هذا الكود بأي تحقق تلقائي عبر GET من نوع
                # /models قبل أو بعد هذا الخطأ — الطلب الوحيد المرسَل هو
                # POST واحد إلى chat/completions أعلاه. الـ 404 هنا يعني
                # أن Groq رفض اسم الموديل المرسَل ضمن هذا الـ POST نفسه.
                raise RuntimeError(
                    f"Groq رفض الموديل '{self.model}' بخطأ 404 (model_not_found) على "
                    "طلب POST الوحيد المرسَل لهذا التحليل. لا يوجد أي طلب GET يقوم به "
                    "هذا الكود من تلقاء نفسه — تحقق يدوياً من اسم الموديل الحالي في "
                    "لوحة تحكم Groq، أو اضبط GROQ_MODEL في متغيرات البيئة."
                ) from e
            if e.response is not None and e.response.status_code == 401:
                raise RuntimeError("Groq 401 — مفتاح GROQ_API_KEY غير صالح أو منتهي.") from e
            raise
        # بعض نماذج الاستدلال (مثل deepseek-r1-distill) قد تُرجع خطوات
        # تفكير داخل وسم <think>...</think> قبل الإجابة النهائية؛ نزيلها
        # لأن analysis.py يتوقع JSON نظيف فقط في النص.
        text = data["choices"][0]["message"]["content"]
        text = _strip_reasoning_tags(text)
        return LLMResponse(self.name, self.model, text, data, latency)


class GeminiProvider(LLMProvider):
    """
    ملاحظات حول خطأ 404 NOT_FOUND الشائع مع Gemini:
    - الرابط v1beta بالصيغة:
      https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
      كان صحيحاً أصلاً؛ سبب الـ 404 غالباً هو اسم موديل تم إيقافه أو
      تقييد الوصول إليه (مثل "gemini-2.5-pro" على بعض المفاتيح/المناطق)،
      وليس خطأ في بناء الرابط نفسه.
    - الحل: استخدام alias يتحدّث تلقائياً بدل اسم إصدار مثبّت، مع إمكانية
      تجاوزه عبر GEMINI_MODEL في حال احتجت موديل محدد.
    - المصادقة أيضاً أصبحت تُرسل عبر الهيدر x-goog-api-key (بدل ?key=
      في الرابط) تفادياً لتسريب المفتاح داخل السجلات (logs) التي قد
      تحتفظ بالـ URL كاملاً.
    """

    name = "gemini"
    API_VERSION = "v1beta"
    # ملاحظة: طُلب صراحة استخدام "gemini-1.5-flash". هذا الاسم لا يزال
    # يعمل لدى كثير من المفاتيح لكن جوجل بدأت تقيّد الوصول لموديلات 1.5
    # القديمة على بعض المشاريع/المناطق (نفس نمط الخطأ 404 الذي وصلنا سابقاً).
    # إن ظهر 404 مجدداً، بدّله فوراً عبر متغير البيئة GEMINI_MODEL إلى
    # "gemini-flash-latest" (alias يتحدّث تلقائياً) دون تعديل الكود.
    DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or os.environ["GEMINI_API_KEY"]
        self.model = model or os.environ.get("GEMINI_MODEL", self.DEFAULT_MODEL)

    def _build_url(self) -> str:
        model_path = self.model if self.model.startswith("models/") else f"models/{self.model}"
        return f"https://generativelanguage.googleapis.com/{self.API_VERSION}/{model_path}:generateContent"

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        url = self._build_url()
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
        }
        try:
            data, latency = self._timed_post(url, headers, payload)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                # نفس الملاحظة: لا يوجد أي طلب GET تلقائي هنا أيضاً — الطلب
                # الوحيد هو POST إلى generateContent أعلاه. الرابط أدناه نص
                # إرشادي فقط لمراجعة يدوية، لا استدعاء فعلي.
                raise RuntimeError(
                    f"Gemini رفض الموديل '{self.model}' بخطأ 404 على طلب POST الوحيد "
                    f"المرسَل لهذا التحليل (الرابط: {url}). لا استدعاء GET تلقائياً من "
                    "هذا الكود — إن احتجت المراجعة يدوياً استخدم متغير البيئة GEMINI_MODEL "
                    "لضبط موديل بديل (مثل alias 'gemini-flash-latest')."
                ) from e
            raise

        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError) as e:
            raise RuntimeError(f"استجابة Gemini غير متوقعة الشكل: {json.dumps(data)[:300]}") from e
        return LLMResponse(self.name, self.model, text, data, latency)


def _strip_reasoning_tags(text: str) -> str:
    """يزيل وسوم <think>...</think> التي تُرجعها بعض نماذج الاستدلال
    (مثل deepseek-r1-distill عبر Groq) قبل إجابتها النهائية بصيغة JSON."""
    import re
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


class MockProvider(LLMProvider):
    """
    مزود احتياطي محلي بالكامل (بدون أي اتصال شبكة).
    يُستخدم فقط كخط دفاع أخير عندما تفشل جميع مزودات الـ API الحقيقية،
    حتى لا يتوقف تشغيل الـ Agent بالكامل بسبب مشكلة مفتاح/شبكة مؤقتة.

    يُنتج تحليلاً "متحفّظاً" مبنياً على قواعد بسيطة (heuristics) لا على
    نموذج لغوي فعلي: severity=high/critical → يُعتبر تهديداً حقيقياً
    يستحق المراجعة اليدوية، غير ذلك → منخفض الثقة ويُطلب تأكيد بشري.
    هذا ليس بديلاً عن تحليل LLM حقيقي؛ الهدف إبقاء خط الأنابيب (pipeline)
    يعمل ومنتجاً لنتائج قابلة للمراجعة، لا اتخاذ قرارات أمنية نهائية.
    """

    name = "mock"

    def complete(self, system_prompt: str, user_prompt: str,
                 max_tokens: int = 1024, temperature: float = 0.2) -> LLMResponse:
        try:
            payload = json.loads(user_prompt)
        except json.JSONDecodeError:
            payload = {}

        severity = str(payload.get("severity", "medium")).lower()
        rule_id = payload.get("rule_id", "UNKNOWN_RULE")
        target = payload.get("target", "unknown")
        is_high_risk = severity in {"high", "critical"}

        result = {
            "is_false_positive": False,
            "confidence": 0.3,  # ثقة منخفضة عمداً لأنه تحليل احتياطي وليس LLM حقيقي
            "risk_level": severity if severity in {"critical", "high", "medium", "low"} else "medium",
            "business_impact": (
                f"[تحليل احتياطي محلي - بدون LLM] بلاغ '{rule_id}' على '{target}' "
                f"بمستوى خطورة {severity} من الفاحص الأصلي. يتطلب مراجعة يدوية "
                "لعدم توفر تحليل ذكاء اصطناعي فعلي في هذه اللحظة."
            ),
            "remediation_explanation": (
                "لم يتم توليد خطة إصلاح فعلية لأن كل مزودات الـ LLM كانت غير متاحة. "
                "يُرجى مراجعة الوصف الأصلي للثغرة يدوياً، أو إعادة المحاولة بعد "
                "التأكد من صلاحية مفاتيح API."
            ),
            "remediation_code": "",
        }
        if not is_high_risk:
            # للمخاطر المنخفضة/المتوسطة نفترض احتمال أعلى لكونها false positive
            # يحتاج تأكيد بشري لاحقاً، لتقليل الضجيج التلقائي أثناء انقطاع الـ LLM
            result["confidence"] = 0.25

        text = json.dumps(result, ensure_ascii=False)
        return LLMResponse(self.name, "local-mock-v1", text, {"mock": True}, latency_ms=0, is_fallback=True)


class LLMRouter:
    """
    يختار المزود المناسب حسب الاسم، ويدعم fallback تلقائي:
    إن فشل المزود الأساسي (rate limit / 404 / انقطاع)، ينتقل للتالي في
    القائمة. المزود المحلي 'mock' يُضاف تلقائياً كخط دفاع أخير (اختياري
    عبر use_mock_fallback) بحيث لا يتوقف الـ Agent كلياً عند فشل الجميع.
    """

    def __init__(self, providers: dict[str, LLMProvider], order: list[str]):
        self.providers = providers
        self.order = order

    @classmethod
    def from_env(cls, use_mock_fallback: bool = False) -> "LLMRouter":
        """
        ترتيب الأولوية الافتراضي: Groq ثم Gemini (مجانيان) قبل Claude/OpenAI
        (مدفوعان). قراءة كل مفتاح تمر عبر _read_key() التي تتجاهل قيماً
        فارغة أو أسطراً بيضاء فقط (خطأ شائع عند نسخ المفتاح من .env بمسافة
        زائدة) بدل معاملتها كمفتاح "موجود" فعلياً.

        use_mock_fallback افتراضياً False: الاعتماد الكامل على مزود حقيقي.
        إن فشلت كل المزودات الحقيقية، تُرفع RuntimeError واضحة بدل تحليل
        وهمي صامت. فعّلها صراحةً (True) فقط لأغراض الاختبار المحلي بدون
        اتصال إنترنت — لا يُنصح بتفعيلها في بيئة الإنتاج.
        """
        providers: dict[str, LLMProvider] = {}
        order: list[str] = []

        groq_key = _read_key("GROQ_API_KEY")
        if groq_key:
            providers["groq"] = GroqProvider(api_key=groq_key)
            order.append("groq")

        gemini_key = _read_key("GEMINI_API_KEY")
        if gemini_key:
            providers["gemini"] = GeminiProvider(api_key=gemini_key)
            order.append("gemini")

        claude_key = _read_key("ANTHROPIC_API_KEY")
        if claude_key:
            providers["claude"] = ClaudeProvider(api_key=claude_key)
            order.append("claude")

        openai_key = _read_key("OPENAI_API_KEY")
        if openai_key:
            providers["openai"] = OpenAIProvider(api_key=openai_key)
            order.append("openai")

        if not providers:
            raise RuntimeError(
                "لا يوجد أي مفتاح API حقيقي صالح (GROQ_API_KEY متاح مجاناً عبر "
                "console.groq.com، وGEMINI_API_KEY عبر aistudio.google.com). "
                "الـ Mock fallback معطّل افتراضياً، فلا يمكن المتابعة دون مزود "
                "حقيقي واحد على الأقل."
            )

        logger.info("مزودات LLM المفعّلة بالترتيب: %s", " → ".join(order))

        if use_mock_fallback:
            providers["mock"] = MockProvider()
            order.append("mock")
            logger.warning(
                "تم تفعيل MockProvider كخط دفاع أخير صراحةً (use_mock_fallback=True) "
                "— لا يُنصح بهذا في بيئة الإنتاج."
            )

        return cls(providers, order=order)

    def complete(self, system_prompt: str, user_prompt: str, **kwargs) -> LLMResponse:
        last_err: Optional[Exception] = None
        for idx, name in enumerate(self.order):
            provider = self.providers.get(name)
            if not provider:
                continue
            try:
                response = provider.complete(system_prompt, user_prompt, **kwargs)
                if response.is_fallback:
                    logger.warning("تم استخدام المزود الاحتياطي المحلي (mock) — النتيجة منخفضة الثقة.")
                elif idx > 0:
                    logger.info(
                        "تم إكمال التحليل عبر المزود الاحتياطي '%s' بعد فشل '%s'.",
                        name, self.order[idx - 1],
                    )
                return response
            except RateLimitError as e:
                logger.warning(
                    "المزود '%s' تجاوز حد الطلبات (rate limit) — تبديل فوري بدون انتظار "
                    "إلى المزود التالي (%s).",
                    name, self.order[idx + 1] if idx + 1 < len(self.order) else "لا يوجد",
                )
                last_err = e
            except requests.exceptions.RequestException as e:
                logger.warning(
                    "المزود '%s' واجه خطأ اتصال (%s) — تبديل فوري إلى المزود التالي (%s).",
                    name, type(e).__name__,
                    self.order[idx + 1] if idx + 1 < len(self.order) else "لا يوجد",
                )
                last_err = e
            except Exception as e:  # noqa: BLE001
                logger.warning("فشل المزود '%s': %s، جارٍ التجربة مع التالي...", name, e)
                last_err = e

        raise RuntimeError(f"فشلت كل المزودات المتاحة (بما فيها الاحتياطي إن وُجد): {last_err}")
