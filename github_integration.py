"""
github_integration.py
----------------------
طبقة الربط مع GitHub باستخدام PyGithub (أبسط للعمليات المركّبة مثل PR).
تدعم: قراءة الملفات، فحصها، ثم فتح Pull Request يحتوي على الإصلاح —
سواء كان الإصلاح ملفاً كاملاً (full_file) أو Unified Diff صغير (diff)
يُطبَّق برمجياً على المحتوى الأصلي عبر apply_unified_diff() أدناه.

التثبيت: pip install PyGithub
المصادقة: يفضّل استخدام Fine-grained Personal Access Token
(صلاحيات: Contents: Read & Write, Pull requests: Read & Write)
محفوظ في متغير بيئة GITHUB_TOKEN — لا تكتبه أبداً داخل الكود.
"""

from __future__ import annotations
import base64
import logging
import os
import re
from dataclasses import dataclass

from github import Github, GithubException

logger = logging.getLogger("devsecops_agent.github")

# الملفات التي يستهدفها الفحص الأولي في الـ MVP
SCAN_TARGET_FILES = ["Dockerfile", "docker-compose.yml", "requirements.txt",
                      ".github/workflows", "nginx.conf"]

_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified_diff(original_content: str, diff_text: str) -> str:
    """
    يطبّق Unified Diff بسيط (كما ينتجه النموذج في analysis.py عندما
    patch_type == "diff") على محتوى ملف أصلي، ويعيد المحتوى الناتج.

    تطبيق يدوي خفيف (بدون مكتبة خارجية مثل `patch`) — يكفي للحالات
    الشائعة (تعديل/إضافة/حذف بضعة أسطر ضمن hunk واحد أو أكثر). لثغرات
    أعقد أو diffs متعددة الملفات، يُفضَّل تشغيل fixup يدوي بدل الاعتماد
    عليه بشكل أعمى — لهذا كل استدعاء له هنا مُغلَّف بـ try/except في
    الطبقة الأعلى (agent.py) بحيث يتجاهل PR الفاشل بدل إيقاف الفحص كله.
    """
    orig_lines = original_content.splitlines(keepends=True)
    diff_lines = diff_text.splitlines()

    result: list[str] = []
    orig_idx = 0  # مؤشر 0-based داخل orig_lines
    i = 0
    n = len(diff_lines)
    applied_any_hunk = False

    while i < n:
        line = diff_lines[i]

        if line.startswith("--- ") or line.startswith("+++ ") or line.startswith("diff ") or line.startswith("index "):
            i += 1
            continue

        m = _HUNK_HEADER_RE.match(line)
        if m:
            applied_any_hunk = True
            old_start = int(m.group(1))
            # انسخ أي أسطر أصلية قبل بداية الـ hunk لم تُنسخ بعد
            gap = (old_start - 1) - orig_idx
            if gap < 0:
                raise ValueError(
                    f"تسلسل hunks غير متوافق مع الملف الأصلي عند السطر {old_start}"
                )
            result.extend(orig_lines[orig_idx:orig_idx + gap])
            orig_idx += gap
            i += 1

            while i < n and not _HUNK_HEADER_RE.match(diff_lines[i]) \
                    and not diff_lines[i].startswith("--- "):
                hline = diff_lines[i]
                if hline.startswith("\\"):  # "\ No newline at end of file"
                    pass
                elif hline.startswith("-"):
                    orig_idx += 1  # سطر محذوف من الأصل — لا يُنسخ
                elif hline.startswith("+"):
                    result.append(hline[1:] + "\n")
                elif hline.startswith(" ") or hline == "":
                    if orig_idx < len(orig_lines):
                        result.append(orig_lines[orig_idx])
                    orig_idx += 1
                else:
                    # سطر سياق بدون بادئة واضحة — نتعامل معه كسياق غير معدَّل
                    if orig_idx < len(orig_lines):
                        result.append(orig_lines[orig_idx])
                    orig_idx += 1
                i += 1
            continue

        i += 1

    if not applied_any_hunk:
        raise ValueError("لم يتم العثور على أي hunk صالح (@@ ... @@) داخل الـ diff المُرسَل")

    result.extend(orig_lines[orig_idx:])
    return "".join(result)


@dataclass
class RepoFile:
    path: str
    content: str
    sha: str


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token or os.environ["GITHUB_TOKEN"]
        self.client = Github(self.token)

    def get_repo(self, full_name: str):
        """full_name مثل: 'org-name/repo-name'"""
        return self.client.get_repo(full_name)

    def read_file(self, full_name: str, path: str, ref: str = "main") -> RepoFile:
        repo = self.get_repo(full_name)
        f = repo.get_contents(path, ref=ref)
        content = base64.b64decode(f.content).decode("utf-8", errors="replace")
        return RepoFile(path=path, content=content, sha=f.sha)

    def list_candidate_files(self, full_name: str, ref: str = "main") -> list[str]:
        """يبحث عن الملفات الحساسة أمنياً الموجودة فعلياً في الريبو."""
        repo = self.get_repo(full_name)
        found = []
        try:
            tree = repo.get_git_tree(ref, recursive=True).tree
        except GithubException as e:
            logger.error("تعذر قراءة شجرة الملفات: %s", e)
            return found
        for item in tree:
            if item.type != "blob":
                continue
            for target in SCAN_TARGET_FILES:
                if item.path == target or item.path.startswith(target):
                    found.append(item.path)
        return found

    def list_source_files(self, full_name: str, ref: str = "main",
                           extensions: tuple[str, ...] = (".py",),
                           ignored_dirs: tuple[str, ...] = (
                               ".git", "venv", ".venv", "node_modules",
                               "__pycache__", "dist", "build", "migrations",
                           ),
                           max_files: int = 500) -> list[str]:
        """
        يعيد مسارات كل ملفات الكود المصدري في الريبو المطابقة للامتدادات
        المطلوبة (افتراضياً .py فقط، لأن سكانر RCE الحالي بنيوي/AST خاص
        بـ Python — أضف امتدادات GENERIC_SCAN_EXTENSIONS من rce_scanner
        لتغطية الكشف النصي الاحتياطي على لغات أخرى إن رغبت).
        max_files يحدّ من عدد الملفات المُعادة لتفادي فحص ريبو ضخم دفعة
        واحدة دون قصد (يمكن رفعه صراحةً عند الحاجة).
        """
        repo = self.get_repo(full_name)
        found: list[str] = []
        try:
            tree = repo.get_git_tree(ref, recursive=True).tree
        except GithubException as e:
            logger.error("تعذر قراءة شجرة الملفات: %s", e)
            return found
        for item in tree:
            if item.type != "blob" or not item.path.endswith(extensions):
                continue
            if any(f"/{d}/" in f"/{item.path}/" or item.path.startswith(f"{d}/") for d in ignored_dirs):
                continue
            found.append(item.path)
            if len(found) >= max_files:
                logger.warning("تم بلوغ الحد الأقصى max_files=%d — قد تتبقى ملفات لم تُفحص.", max_files)
                break
        return found

    def read_files_bulk(self, full_name: str, paths: list[str], ref: str = "main") -> dict[str, str]:
        """
        يقرأ عدة ملفات دفعة واحدة ويعيدها كقاموس {مسار: محتوى} — الصيغة
        التي يتوقعها scanners.rce_scanner.scan_files() مباشرة. يتجاهل أي
        ملف يتعذر قراءته (محذوف بين لحظة get_git_tree والقراءة، ثنائي
        غير قابل للترميز كنص، إلخ) ويسجل تحذيراً بدل إيقاف الفحص كله.
        """
        result: dict[str, str] = {}
        for path in paths:
            try:
                result[path] = self.read_file(full_name, path, ref=ref).content
            except Exception as e:  # noqa: BLE001
                logger.warning("تعذر قراءة %s: %s — تم تخطيه.", path, e)
        return result

    def resolve_fixed_content(self, original_content: str, remediation_code: str,
                               patch_type: str | None) -> str:
        """
        يحدّد المحتوى النهائي الذي يجب رفعه للملف بناءً على patch_type
        القادم من analysis.py:
          - "diff": يُطبَّق remediation_code كـ Unified Diff على المحتوى الأصلي.
          - غير ذلك (None أو "full_file"): يُعتبر remediation_code هو
            محتوى الملف الكامل بعد الإصلاح، ويُستخدم كما هو.
        يرفع ValueError بوضوح إن تعذّر تطبيق الـ diff، ليتم التقاطها في
        الطبقة الأعلى (agent.py) وتخطي هذا الـ PR بدل إيقاف الفحص كله.
        """
        if patch_type == "diff":
            return apply_unified_diff(original_content, remediation_code)
        return remediation_code

    def open_remediation_pr(
        self,
        full_name: str,
        base_branch: str,
        file_path: str,
        original_sha: str,
        fixed_content: str,
        vulnerability_summary: str,
        branch_prefix: str = "security-fix",
    ) -> str:
        """
        ينشئ فرعاً جديداً، يحدّث الملف بالمحتوى المُصلَح، ثم يفتح PR.
        يعيد رابط الـ Pull Request.
        """
        repo = self.get_repo(full_name)
        base_ref = repo.get_git_ref(f"heads/{base_branch}")
        new_branch = f"{branch_prefix}/{file_path.replace('/', '-')}-{original_sha[:7]}"

        try:
            repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_ref.object.sha)
        except GithubException as e:
            if "Reference already exists" not in str(e):
                raise

        repo.update_file(
            path=file_path,
            message=f"security(auto-fix): إصلاح ثغرة في {file_path}",
            content=fixed_content,
            sha=original_sha,
            branch=new_branch,
        )

        pr = repo.create_pull(
            title=f"🔒 إصلاح أمني تلقائي: {file_path}",
            body=(
                "تم إنشاء هذا الـ PR تلقائياً بواسطة DevSecOps AI Agent.\n\n"
                f"**الملف المتأثر:** `{file_path}`\n\n"
                f"**ملخص الثغرة والإصلاح:**\n{vulnerability_summary}\n\n"
                "⚠️ يُرجى مراجعة التغييرات قبل الدمج (Human-in-the-loop review)."
            ),
            head=new_branch,
            base=base_branch,
        )
        return pr.html_url
