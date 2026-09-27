# DevSecOps & Security AI Agent — MVP

هيكل جاهز للبدء الفوري في بناء الـ Agent المطلوب لحاضنة ZINC.

## 1. البنية

```
devsecops_agent/
├── agent.py               # نقطة الدخول (orchestrator)
├── analysis.py            # التحليل: تصفية False Positives + توليد الإصلاح
├── llm_providers.py       # طبقة موحّدة لـ Claude / OpenAI / Gemini عبر REST
├── github_integration.py  # قراءة الملفات وفتح Pull Requests تلقائياً
├── memory.py              # الذاكرة والتعلّم المستمر (SQLite)
├── sample_report.json     # مثال لتقرير فحص أمني
└── requirements.txt
```

## 2. التثبيت

```bash
python -m venv venv
source venv/bin/activate        # على ويندوز: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. متغيرات البيئة (لا تكتب أي مفتاح داخل الكود)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."      # أو أي واحد/أكثر من الثلاثة التالية
export OPENAI_API_KEY="sk-..."
export GEMINI_API_KEY="AIza..."
export GITHUB_TOKEN="github_pat_..."       # صلاحيات Contents + Pull requests فقط
```

`LLMRouter.from_env()` يكتشف تلقائياً أي المفاتيح متوفرة، ويستخدمها بالترتيب
مع fallback تلقائي إن فشل أحد المزودين (rate limit مثلاً).

## 4. التشغيل التجريبي (بدون GitHub حقيقي)

```bash
python agent.py --repo "your-org/your-repo" --report sample_report.json --no-pr
```

هذا يحلل البلاغات ويطبع النتائج والإحصائيات دون فتح أي Pull Request —
مفيد لاختبار جودة التحليل أولاً.

## 5. التشغيل الكامل مع فتح PR فعلي

```bash
python agent.py --repo "your-org/your-repo" --report sample_report.json --branch main
```

سيقوم الـ Agent بـ:
1. تحليل كل بلاغ عبر الـ LLM مع الاستعانة بالسياق التاريخي من `memory.py`.
2. تجاهل ما يُصنَّف False Positive (مع تسجيله في الذاكرة).
3. لكل ثغرة حقيقية لها كود إصلاح، فتح فرع جديد + Pull Request يحتوي
   على الإصلاح المقترح (مراجعة بشرية قبل الدمج — Human-in-the-loop).

## 6. حلقة التعلّم المستمر (Self-Improvement Loop)

بعد أن يراجع فريقك أي بلاغ (سواء وافقتم على أنه ثغرة حقيقية أو اعتبرتموه
بلاغاً خاطئاً)، سجّلوا القرار في الذاكرة:

```python
from memory import AgentMemory
memory = AgentMemory(db_path="your-org_your-repo_memory.sqlite3")
memory.record_human_label(finding_id=42, label="false_positive")
```

في المرة القادمة التي يظهر فيها بلاغ من نفس النوع (`rule_id` + `target`)،
سيُمرَّر هذا القرار كسياق ضمن الـ prompt (انظر `get_prior_context` في
`memory.py`)، فترتفع دقة تصنيف النموذج تدريجياً دون الحاجة لإعادة تدريب
أي نموذج — كل ما يحدث هو "حقن سياق" (context injection) ذكي.

## 7. خطوات التوسّع بعد الـ MVP

- ربط مصدر فحص حقيقي (OWASP ZAP API أو Trivy لفحص صور Docker) بدل
  ملف JSON يدوي — فقط حوّل مخرجاته لنفس صيغة `findings` في `agent.py`.
- ترقية `memory.py` من SQLite إلى Postgres عند الحاجة لتعدد المستخدمين.
- إضافة webhook من GitHub Actions يستدعي `agent.py` تلقائياً بعد كل push.
- إضافة طبقة تحقق متقاطع (ask 2 providers, compare) لتقليل الأخطاء عبر
  تمرير نفس البلاغ لأكثر من مزود ومقارنة النتائج قبل اتخاذ القرار النهائي.