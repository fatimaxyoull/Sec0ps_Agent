"""
memory.py
---------
طبقة الذاكرة والتعلّم المستمر (Continuous Learning Loop).

بدلاً من إعادة تحليل كل شيء من الصفر في كل فحص، يحتفظ الـ Agent بـ:
1) سجل كامل للفحوصات السابقة ونتائجها (findings).
2) قرارات المستخدم/الفريق حول كل بلاغ: مؤكد (confirmed) أو
   بلاغ خاطئ (false_positive) — هذا هو "التعلّم" الفعلي.
3) عند ظهور بلاغ مشابه لاحقاً (نفس القاعدة + نفس السياق)، يراجع
   الـ Agent القرار السابق ويستخدمه كسياق (context) يُمرَّر لطلب الـ LLM،
   فترتفع دقة التصنيف ويقل عدد الأسئلة المكررة على الفريق الأمني.

المخزّن: SQLite (ملف واحد) — كافٍ لمرحلة MVP وقابل للترقية لاحقاً إلى
Postgres دون تغيير الواجهة العامة لهذه الوحدة.
"""

from __future__ import annotations
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("devsecops_agent.memory")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    created_at REAL NOT NULL,
    raw_report TEXT NOT NULL
);

-- ملاحظة: CREATE TABLE IF NOT EXISTS يُنشئ الجدول الكامل فقط إذا لم يكن
-- موجوداً أصلاً. إن كانت قاعدة بيانات قديمة موجودة مسبقاً بدون بعض هذه
-- الأعمدة (مثل patch_type/language)، فهذا السطر لن يضيفها — لهذا توجد
-- خطوة _migrate() أدناه في AgentMemory.__init__ تتكفّل بذلك تلقائياً.
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    target TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    llm_verdict TEXT,
    llm_confidence REAL,
    human_label TEXT,              -- 'confirmed' / 'false_positive' / NULL
    remediation_code TEXT,
    patch_type TEXT,               -- 'diff' / 'full_file' / NULL
    language TEXT,                 -- لغة/نوع الملف المتأثر (nginx, dockerfile, python...)
    pr_url TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

-- فهرس يسرّع البحث عن "هل رأينا هذا النوع من البلاغ من قبل؟"
CREATE INDEX IF NOT EXISTS idx_findings_rule_target
    ON findings(rule_id, target);
"""

# ---------------------------------------------------------------------
# أعمدة findings "الاختيارية" (كل ما عدا id/scan_id والأعمدة NOT NULL
# الأساسية) مع نوعها في SQLite — تُستخدم في الـ migration التلقائي:
# أي عمود من هذه القائمة غير موجود في قاعدة بيانات قديمة يُضاف تلقائياً
# عبر ALTER TABLE بدل أن يفشل البرنامج بـ "no such column". أضف أي عمود
# جديد تحتاجه مستقبلاً هنا وفي SCHEMA أعلاه معاً، ولن تحتاج أي خطوة
# migration يدوية بعدها.
# ---------------------------------------------------------------------
FINDINGS_OPTIONAL_COLUMNS: dict[str, str] = {
    "llm_verdict": "TEXT",
    "llm_confidence": "REAL",
    "human_label": "TEXT",
    "remediation_code": "TEXT",
    "patch_type": "TEXT",
    "language": "TEXT",
    "pr_url": "TEXT",
}


@dataclass
class Finding:
    rule_id: str
    target: str
    severity: str
    description: str
    llm_verdict: Optional[str] = None
    llm_confidence: Optional[float] = None
    human_label: Optional[str] = None
    remediation_code: Optional[str] = None
    patch_type: Optional[str] = None
    language: Optional[str] = None
    pr_url: Optional[str] = None


class AgentMemory:
    def __init__(self, db_path: str = "agent_memory.sqlite3"):
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """
        ترقية تلقائية وآمنة لقواعد بيانات قديمة: تفحص الأعمدة الفعلية
        الموجودة في جدول findings عبر PRAGMA table_info، وتضيف عبر
        ALTER TABLE ... ADD COLUMN أي عمود متوقَّع (FINDINGS_OPTIONAL_COLUMNS)
        غير موجود بعد. آمنة للتشغيل في كل مرة (idempotent) — لا تفعل شيئاً
        إن كانت الأعمدة موجودة أصلاً، ولا تلمس أي بيانات محفوظة.
        """
        existing_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(findings)")}
        added = []
        for col, col_type in FINDINGS_OPTIONAL_COLUMNS.items():
            if col not in existing_cols:
                self._conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {col_type}")
                added.append(col)
        if added:
            self._conn.commit()
            logger.info("تمت ترقية قاعدة البيانات %s تلقائياً — أُضيفت الأعمدة: %s",
                        self.db_path, ", ".join(added))

    # ---------- كتابة ----------
    def start_scan(self, repo: str, raw_report: dict) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans (repo, created_at, raw_report) VALUES (?, ?, ?)",
            (repo, time.time(), json.dumps(raw_report, ensure_ascii=False)),
        )
        self._conn.commit()
        return cur.lastrowid

    def add_finding(self, scan_id: int, finding: Finding) -> int:
        cur = self._conn.execute(
            """INSERT INTO findings
               (scan_id, rule_id, target, severity, description,
                llm_verdict, llm_confidence, human_label,
                remediation_code, patch_type, language, pr_url)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, finding.rule_id, finding.target, finding.severity,
             finding.description, finding.llm_verdict, finding.llm_confidence,
             finding.human_label, finding.remediation_code,
             finding.patch_type, finding.language, finding.pr_url),
        )
        self._conn.commit()
        return cur.lastrowid

    def record_human_label(self, finding_id: int, label: str) -> None:
        """label: 'confirmed' أو 'false_positive' — هذا ما يغذّي التعلّم المستقبلي."""
        self._conn.execute(
            "UPDATE findings SET human_label = ? WHERE id = ?", (label, finding_id)
        )
        self._conn.commit()

    # ---------- قراءة / استرجاع للسياق ----------
    def get_prior_context(self, rule_id: str, target: str, limit: int = 5) -> list[dict]:
        """
        يعيد آخر قرارات بشرية معروفة لنفس نوع الثغرة/الهدف، لتُستخدم
        كسياق (few-shot context) داخل الـ prompt المرسل للـ LLM، بحيث
        تقل نسبة تكرار نفس الخطأ في التصنيف.
        """
        rows = self._conn.execute(
            """SELECT description, human_label, llm_verdict
               FROM findings
               WHERE rule_id = ? AND target = ? AND human_label IS NOT NULL
               ORDER BY id DESC LIMIT ?""",
            (rule_id, target, limit),
        ).fetchall()
        return [
            {"description": r[0], "human_label": r[1], "previous_llm_verdict": r[2]}
            for r in rows
        ]

    def get_scan_findings(self, scan_id: int) -> list[dict]:
        """يعيد كل بلاغات فحص معيّن — يُستخدم لتوليد التقرير النهائي."""
        rows = self._conn.execute(
            """SELECT id, rule_id, target, severity, description,
                      llm_verdict, llm_confidence, human_label,
                      remediation_code, patch_type, language, pr_url
               FROM findings WHERE scan_id = ? ORDER BY
                 CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2 ELSE 3 END""",
            (scan_id,),
        ).fetchall()
        cols = ["id", "rule_id", "target", "severity", "description",
                "llm_verdict", "llm_confidence", "human_label",
                "remediation_code", "patch_type", "language", "pr_url"]
        return [dict(zip(cols, r)) for r in rows]

    def get_scan_meta(self, scan_id: int) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT repo, created_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return {"repo": row[0], "created_at": row[1]} if row else None

    def stats(self) -> dict:
        total = self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        fp = self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE human_label = 'false_positive'"
        ).fetchone()[0]
        confirmed = self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE human_label = 'confirmed'"
        ).fetchone()[0]
        return {"total_findings": total, "false_positives": fp, "confirmed": confirmed}

    def close(self):
        self._conn.close()
