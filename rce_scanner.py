"""
scanners/rce_scanner.py
------------------------
سكانر فحص أمني ثابت (Static Analysis / SAST) متخصص باكتشاف ثغرات حقن
الأكواد وتنفيذ الأوامر عن بُعد (Code Injection / Remote Code Execution)
في كود Python، بالإضافة لتغطية احتياطية بالـ regex لملفات أخرى (Shell،
JS، PHP...) أو عند فشل تحليل AST.

الأنماط المكتشفة (حسب الطلب):
  - eval() / exec()                              → تنفيذ كود ديناميكي
  - os.system()                                   → تنفيذ أوامر شل مباشر
  - subprocess.* مع shell=True                    → حقن أوامر عبر الشل
  - pickle.load() / pickle.loads()                → إلغاء تسلسل غير آمن

لماذا AST بدل regex فقط لملفات Python:
  الاعتماد على AST (شجرة بنية الكود المُحلَّلة فعلياً بواسطة مُفسِّر
  Python) بدل regex نصي يمنع أغلب الإيجابيات الخاطئة الشائعة: سطر داخل
  تعليق، اسم داخل نص/سلسلة، أو دالة اسمها "eval" ضمن كلاس غير مرتبطة
  بالدالة المدمجة eval(). الـ regex يبقى فقط كخط احتياطي لملفات غير
  Python أو عند تعذّر تحليل الملف (خطأ صياغي، ترميز غير متوقع...).

الناتج متوافق 100% مع صيغة "findings" المستخدمة في sample_report.json
وagent.py — أي يمكن تمريره مباشرة لـ AgentMemory.start_scan() ثم
SecurityAnalyzer.analyze_finding() لكل بلاغ، فيستفيد تلقائياً من:
  - نظام الـ LLM Routing (Groq → Gemini → ...) لتوليد شرح وكود إصلاح.
  - REMEDIATION_HINTS في analysis.py (أُضيفت له تلميحات خاصة بهذه
    الأنماط الخمسة لرفع جودة الإصلاح المقترح).
  - فتح Pull Request تلقائي عبر github_integration.py إن أمكن.
  - الظهور في تقرير Markdown/HTML النهائي عبر report.py.
"""

from __future__ import annotations
import ast
import logging
import os
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger("devsecops_agent.scanners.rce")

# ---------------------------------------------------------------------
# تعريف القواعد: rule_id -> (severity, وصف عربي مختصر يُستخدم في البلاغ)
# القيم هنا يجب أن تبقى متوافقة مع REMEDIATION_HINTS في analysis.py
# (المطابقة substring-based على rule_id) حتى يحصل كل بلاغ على تلميح
# إصلاح دقيق بدل الاعتماد على معرفة النموذج العامة فقط.
# ---------------------------------------------------------------------
RULES: dict[str, tuple[str, str]] = {
    "PY_EVAL_USAGE": (
        "critical",
        "استخدام eval() لتنفيذ نص كسطر كود Python — إذا كان المدخل (أو جزء "
        "منه) قادماً من مستخدم غير موثوق، فهذه ثغرة حقن كود مباشرة (RCE).",
    ),
    "PY_EXEC_USAGE": (
        "critical",
        "استخدام exec() لتنفيذ كتلة كود Python ديناميكياً — نفس مخاطر "
        "eval() تقريباً، مع إمكانية تنفيذ أوامر متعددة الأسطر.",
    ),
    "PY_OS_SYSTEM": (
        "high",
        "استخدام os.system() لتشغيل أمر عبر الشل — إن كان جزء من الأمر "
        "مبنياً على مدخل مستخدم، فهذه ثغرة حقن أوامر (Command Injection).",
    ),
    "PY_SUBPROCESS_SHELL_TRUE": (
        "high",
        "استدعاء subprocess مع shell=True — يمرر السلسلة كاملة لمفسّر "
        "الشل، ما يفتح الباب لحقن أوامر إضافية عبر ; أو | أو && إن كان "
        "أي جزء من السلسلة قادماً من مدخل غير موثوق.",
    ),
    "PY_PICKLE_LOAD": (
        "critical",
        "إلغاء تسلسل بيانات عبر pickle.load()/loads() — تنسيق pickle "
        "يسمح بتنفيذ كود عشوائي أثناء فك التسلسل؛ إلغاء تسلسل بيانات "
        "غير موثوقة بهذه الطريقة يُعادل RCE مباشرة في أغلب الحالات.",
    ),
}

# نفس القواعد بنسخة "GENERIC" لملفات غير Python أو عند فشل AST — نفس
# الخطورة والوصف مع توضيح أن الكشف نصي (regex) وليس تحليلاً بنيوياً.
_GENERIC_SUFFIX = " [كُشف عبر مطابقة نصية (regex) — راجع السياق يدوياً لاستبعاد إيجابية خاطئة من داخل تعليق/سلسلة نصية.]"
GENERIC_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    ("GENERIC_EVAL_USAGE", re.compile(r"\beval\s*\("), *RULES["PY_EVAL_USAGE"]),
    ("GENERIC_EXEC_USAGE", re.compile(r"\bexec\s*\("), *RULES["PY_EXEC_USAGE"]),
    ("GENERIC_OS_SYSTEM", re.compile(r"\bos\.system\s*\("), *RULES["PY_OS_SYSTEM"]),
    ("GENERIC_SHELL_TRUE", re.compile(r"shell\s*=\s*True"), *RULES["PY_SUBPROCESS_SHELL_TRUE"]),
    ("GENERIC_PICKLE_LOAD", re.compile(r"\bpickle\.loads?\s*\("), *RULES["PY_PICKLE_LOAD"]),
]

DEFAULT_SOURCE_EXTENSIONS = (".py",)  # التحليل البنيوي (AST) خاص بـ Python
# ملفات إضافية تُفحص بالـ regex الاحتياطي فقط (لا يوجد AST لها هنا)
GENERIC_SCAN_EXTENSIONS = (".sh", ".js", ".php", ".rb", ".pl")


def _dotted_name(node: ast.AST) -> Optional[str]:
    """يحوّل تعبير استدعاء متسلسل مثل os.system أو subprocess.run إلى
    نص 'os.system' — يعيد None إن لم يكن التعبير بالشكل المتوقع."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _is_truthy_literal(node: ast.AST) -> bool:
    """يتحقق أن قيمة kwarg هي True حرفياً (وليس متغيراً قد يكون False)."""
    return isinstance(node, ast.Constant) and node.value is True


def _snippet(content: str, lineno: int, context: int = 1) -> str:
    """يستخرج السطر المخالف مع سطر سياق قبله وبعده لعرضه في raw_context."""
    lines = content.splitlines()
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    return "\n".join(lines[start:end])


class _RCEVisitor(ast.NodeVisitor):
    """يمشي على شجرة AST لملف Python واحد ويجمع كل استدعاءات الدوال
    الخطيرة المعرّفة في RULES. يتتبع أيضاً الأسماء المستوردة من
    subprocess (import subprocess / from subprocess import run كـ x)
    لرفع دقة اكتشاف الاستدعاءات غير المؤهّلة بالنقطة (run(...) بدل
    subprocess.run(...))."""

    SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

    def __init__(self, path: str, content: str):
        self.path = path
        self.content = content
        self.findings: list[dict] = []
        self.subprocess_module_aliases: set[str] = set()   # import subprocess [as x]
        self.subprocess_local_names: set[str] = set()       # from subprocess import run [as x]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "subprocess":
                self.subprocess_module_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "subprocess":
            for alias in node.names:
                if alias.name in self.SUBPROCESS_FUNCS:
                    self.subprocess_local_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def _add(self, rule_id: str, lineno: int) -> None:
        severity, description = RULES[rule_id]
        self.findings.append({
            "rule_id": rule_id,
            "target": f"{self.path}:{lineno}",
            "severity": severity,
            "description": description,
            "raw_context": _snippet(self.content, lineno),
        })

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        lineno = getattr(node, "lineno", 0)

        # --- eval() / exec() كنداء مباشر (اسم بسيط) ---
        if isinstance(func, ast.Name):
            if func.id == "eval":
                self._add("PY_EVAL_USAGE", lineno)
            elif func.id == "exec":
                self._add("PY_EXEC_USAGE", lineno)
            elif func.id in self.subprocess_local_names and self._has_shell_true(node):
                self._add("PY_SUBPROCESS_SHELL_TRUE", lineno)

        # --- استدعاءات بصيغة module.func(...) ---
        elif isinstance(func, ast.Attribute):
            dotted = _dotted_name(func)
            if dotted:
                if dotted == "os.system":
                    self._add("PY_OS_SYSTEM", lineno)
                elif dotted in {"pickle.load", "pickle.loads",
                                "cPickle.load", "cPickle.loads"}:
                    self._add("PY_PICKLE_LOAD", lineno)
                else:
                    # subprocess.run(...) / sp.Popen(...) إلخ، حسب الاسم
                    # المستعمل فعلياً عند الاستيراد (import subprocess as sp)
                    root = dotted.split(".")[0]
                    func_name = dotted.split(".")[-1]
                    if root in self.subprocess_module_aliases and func_name in self.SUBPROCESS_FUNCS:
                        if self._has_shell_true(node):
                            self._add("PY_SUBPROCESS_SHELL_TRUE", lineno)

        self.generic_visit(node)

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        return any(
            kw.arg == "shell" and _is_truthy_literal(kw.value)
            for kw in node.keywords
        )


def scan_python_source(path: str, content: str) -> list[dict]:
    """يحلل ملف Python واحد عبر AST ويعيد قائمة بلاغات RCE/حقن الأكواد."""
    tree = ast.parse(content, filename=path)  # يرفع SyntaxError إن كان الملف غير صالح
    visitor = _RCEVisitor(path, content)
    visitor.visit(tree)
    return visitor.findings


def scan_generic_source(path: str, content: str) -> list[dict]:
    """كشف احتياطي بالـ regex — يُستخدم لملفات غير Python أو عند فشل AST."""
    findings: list[dict] = []
    lines = content.splitlines()
    for rule_id, pattern, severity, description in GENERIC_PATTERNS:
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                findings.append({
                    "rule_id": rule_id,
                    "target": f"{path}:{i}",
                    "severity": severity,
                    "description": description + _GENERIC_SUFFIX,
                    "raw_context": _snippet(content, i),
                })
    return findings


class RCEScanner:
    """
    واجهة الاستخدام الرئيسية للسكانر. تُبقي التصميم متسقاً مع باقي
    الـ Agent: صنف بسيط بدالة scan() تعيد نفس صيغة "findings" المستخدمة
    في كل مكان آخر بالمشروع (sample_report.json، agent.py).
    """

    def scan_file(self, path: str, content: str) -> list[dict]:
        if path.endswith(".py"):
            try:
                return scan_python_source(path, content)
            except SyntaxError as e:
                logger.warning(
                    "تعذر تحليل %s كـ AST (%s) — التراجع لكشف نصي احتياطي.",
                    path, e,
                )
                return scan_generic_source(path, content)
        if path.endswith(GENERIC_SCAN_EXTENSIONS):
            return scan_generic_source(path, content)
        return []

    def scan(self, files: dict[str, str]) -> dict:
        """files: {مسار_نسبي: محتوى_الملف}. يعيد {'findings': [...]}."""
        all_findings: list[dict] = []
        for path, content in files.items():
            all_findings.extend(self.scan_file(path, content))
        logger.info("RCEScanner: تم فحص %d ملف، %d بلاغ.", len(files), len(all_findings))
        return {"findings": all_findings}


# ---------------------------------------------------------------------
# دوال مساعدة على مستوى الموديول (اختصار شائع بدل إنشاء RCEScanner() يدوياً)
# ---------------------------------------------------------------------

def scan_files(files: dict[str, str]) -> dict:
    """اختصار لـ RCEScanner().scan(files) — الاستخدام الأشيع عند الدمج
    مع نتائج GitHubClient (قاموس {مسار: محتوى} جاهز أصلاً)."""
    return RCEScanner().scan(files)


def scan_directory(root: str, extensions: tuple[str, ...] = DEFAULT_SOURCE_EXTENSIONS
                    + GENERIC_SCAN_EXTENSIONS) -> dict:
    """
    فحص شجرة ملفات محلية (نسخة مستنسخة من الريبو، أو أي مجلد كود) —
    مفيد لتشغيل الفحص محلياً في CI قبل حتى الحاجة لربط GitHub API.
    يتجاهل المجلدات الشائعة غير ذات الصلة (venv، node_modules، .git).
    """
    ignored_dirs = {".git", "venv", ".venv", "node_modules", "__pycache__", "dist", "build"}
    files: dict[str, str] = {}
    root_path = Path(root)
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in ignored_dirs]
        for fname in filenames:
            if fname.endswith(extensions):
                full = Path(dirpath) / fname
                rel = str(full.relative_to(root_path))
                try:
                    files[rel] = full.read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    logger.warning("تعذرت قراءة %s: %s", full, e)
    return scan_files(files)
