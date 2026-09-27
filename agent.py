"""
agent.py
--------
نقطة الدخول الرئيسية (Orchestrator) للـ MVP، بمصدرَي بلاغات مدعومَين:

  1) تقرير فحص أمني جاهز بصيغة JSON (--report) — من أي سكانر خارجي:
     Nikto، ZAP، أو نتائج فحص Headers مخصصة.
  2) فحص كود مصدري حي في الريبو نفسه (--scan-source) — يجلب ملفات
     Python من GitHub مباشرة ويشغّل عليها scanners.rce_scanner
     لاكتشاف ثغرات حقن الأكواد وتنفيذ الأوامر (eval/exec/os.system/
     subprocess shell=True/pickle.load) دون الحاجة لأي تقرير خارجي.

كلا المصدرين يُغذّيان نفس خط الأنابيب المشترك (_process_report):
  - يحلَّل كل بلاغ عبر SecurityAnalyzer، الذي يستخدم LLMRouter (سلسلة
    تبديل ذكي Groq → Gemini → ... حسب المفاتيح المتوفرة في البيئة؛ أي
    429/404/خطأ اتصال على مزود يُبدَّل فوراً للتالي دون توقف الفحص).
  - للبلاغات المؤكدة وذات كود إصلاح على ملف موجود في GitHub، يُفتح
    Pull Request تلقائياً (يدعم إصلاح كامل الملف أو Unified Diff).
  - يُخزَّن كل شيء في AgentMemory ليتحسّن التحليل مستقبلاً، ويُولَّد
    تقرير Markdown/HTML نهائي في مجلد reports/.

تشغيل تجريبي (تقرير JSON جاهز):
    python agent.py --repo "org/repo" --report sample_report.json

تشغيل فحص RCE مباشر على الكود المصدري في الريبو:
    python agent.py --repo "org/repo" --scan-source
"""

from __future__ import annotations
import argparse
import json
import logging
import re

from analysis import SecurityAnalyzer
from github_integration import GitHubClient
from llm_providers import LLMRouter
from memory import AgentMemory
from report import ReportGenerator
from rce_scanner import scan_files

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("devsecops_agent.main")

# بلاغات scanners/rce_scanner.py تستخدم target بصيغة "path/to/file.py:42"
# (لتحديد السطر بدقة في التحليل والتقرير). عند فتح PR نحتاج المسار
# المجرَّد بدون رقم السطر، لأن GitHub API يتعامل مع الملف كاملاً.
_LINE_SUFFIX_RE = re.compile(r":(\d+)$")


def _resolve_file_path(target: str) -> str:
    """يزيل لاحقة ':رقم_السطر' إن وُجدت، ليصبح target مساراً صالحاً لـ
    GitHub API (gh.read_file / gh.open_remediation_pr)."""
    m = _LINE_SUFFIX_RE.search(target)
    return target[:m.start()] if m else target


def _process_report(repo_full_name: str, report: dict, base_branch: str = "main",
                     open_prs: bool = True, reports_dir: str = "reports") -> None:
    """
    خط الأنابيب المشترك: يأخذ تقرير بلاغات (بغضّ النظر عن مصدره — JSON
    ثابت أو نتيجة سكانر مباشر) ويشغّل عليه: التحليل عبر LLMRouter، فتح
    PR للإصلاحات، التخزين في الذاكرة، وتوليد التقرير النهائي.
    """
    memory = AgentMemory(db_path=f"{repo_full_name.replace('/', '_')}_memory.sqlite3")
    router = LLMRouter.from_env()
    analyzer = SecurityAnalyzer(router, memory)
    gh = GitHubClient() if open_prs else None

    scan_id = memory.start_scan(repo_full_name, report)
    logger.info("بدء الفحص #%s للريبو %s — عدد البلاغات: %d",
                scan_id, repo_full_name, len(report.get("findings", [])))

    for item in report.get("findings", []):
        try:
            result, finding_id = analyzer.analyze_finding(
                scan_id=scan_id,
                rule_id=item["rule_id"],
                target=item["target"],
                severity=item["severity"],
                description=item["description"],
                raw_context=item.get("raw_context", ""),
            )
        except Exception as e:  # noqa: BLE001
            logger.error("تعذر تحليل البلاغ %s: %s", item.get("rule_id"), e)
            continue

        if result.is_false_positive:
            logger.info("[FP] %s على %s (ثقة %.2f) — تم تجاهله",
                        item["rule_id"], item["target"], result.confidence)
            continue

        logger.info("[%s] %s على %s — %s",
                    result.risk_level.upper(), item["rule_id"], item["target"],
                    result.business_impact)

        if not open_prs or not result.remediation_code:
            continue

        file_path = _resolve_file_path(item["target"])

        # فتح PR فقط إذا كان الهدف ملفاً حقيقياً في الريبو
        try:
            repo_file = gh.read_file(repo_full_name, file_path, ref=base_branch)
            fixed_content = gh.resolve_fixed_content(
                original_content=repo_file.content,
                remediation_code=result.remediation_code,
                patch_type=result.patch_type,
            )
            pr_url = gh.open_remediation_pr(
                full_name=repo_full_name,
                base_branch=base_branch,
                file_path=file_path,
                original_sha=repo_file.sha,
                fixed_content=fixed_content,
                vulnerability_summary=result.remediation_explanation,
            )
            logger.info("تم فتح Pull Request: %s", pr_url)
        except Exception as e:  # noqa: BLE001
            logger.warning("تعذر فتح PR للملف %s: %s", file_path, e)

    logger.info("إحصائيات الذاكرة التراكمية: %s", memory.stats())

    report_paths = ReportGenerator(memory).generate(scan_id, output_dir=reports_dir)
    logger.info("تقرير Markdown: %s", report_paths.markdown_path)
    logger.info("تقرير HTML: %s", report_paths.html_path)

    memory.close()


def run(repo_full_name: str, report_path: str, base_branch: str = "main",
        open_prs: bool = True, reports_dir: str = "reports") -> None:
    """المسار الأصلي: تقرير فحص جاهز بصيغة JSON. الصيغة المتوقعة:
    {"findings": [{"rule_id": "...", "target": "Dockerfile", "severity": "high",
                    "description": "...", "raw_context": "..."}]}"""
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    _process_report(repo_full_name, report, base_branch=base_branch,
                     open_prs=open_prs, reports_dir=reports_dir)


def run_source_scan(repo_full_name: str, base_branch: str = "main",
                     open_prs: bool = True, reports_dir: str = "reports",
                     max_files: int = 500) -> None:
    """
    مسار جديد: يجلب ملفات .py من الريبو مباشرة عبر GitHub API، يشغّل
    عليها scanners.rce_scanner (كشف eval/exec/os.system/subprocess
    shell=True/pickle.load)، ثم يمرر النتائج لنفس خط الأنابيب المشترك.
    لا حاجة لأي ملف تقرير JSON يدوي في هذا المسار.
    """
    gh = GitHubClient()
    paths = gh.list_source_files(repo_full_name, ref=base_branch)
    logger.info("تم العثور على %d ملف Python للفحص في %s", len(paths), repo_full_name)

    files = gh.read_files_bulk(repo_full_name, paths, ref=base_branch)
    report = scan_files(files)
    logger.info("سكانر RCE: %d بلاغ عبر %d ملف تمت قراءته فعلياً",
                len(report["findings"]), len(files))

    _process_report(repo_full_name, report, base_branch=base_branch,
                     open_prs=open_prs, reports_dir=reports_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DevSecOps Security AI Agent")
    parser.add_argument("--repo", required=True, help="org/repo على GitHub")
    parser.add_argument("--report", help="مسار ملف تقرير الفحص JSON (تجاهله إن استخدمت --scan-source)")
    parser.add_argument("--scan-source", action="store_true",
                         help="فحص ملفات .py في الريبو مباشرة بحثاً عن ثغرات RCE بدل قراءة تقرير JSON")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--no-pr", action="store_true", help="تحليل فقط دون فتح PR")
    parser.add_argument("--reports-dir", default="reports", help="مجلد حفظ تقارير Markdown/HTML")
    args = parser.parse_args()

    if args.scan_source:
        run_source_scan(args.repo, base_branch=args.branch, open_prs=not args.no_pr,
                         reports_dir=args.reports_dir)
    else:
        if not args.report:
            parser.error("مطلوب --report ما لم تستخدم --scan-source")
        run(args.repo, args.report, base_branch=args.branch, open_prs=not args.no_pr,
            reports_dir=args.reports_dir)
