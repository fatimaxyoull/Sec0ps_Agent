"""
report.py
---------
توليد تقرير نهائي (Markdown + HTML) بعد كل فحص، بالاعتماد فقط على
البيانات المخزّنة في AgentMemory (لا حاجة لأي مكتبة خارجية إضافية).

الاستخدام النموذجي (يتم استدعاؤه تلقائياً من agent.py):

    from report import ReportGenerator
    gen = ReportGenerator(memory)
    paths = gen.generate(scan_id, output_dir="reports")
    # paths.markdown_path, paths.html_path
"""

from __future__ import annotations
import html
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from memory import AgentMemory

logger = logging.getLogger("devsecops_agent.report")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_LABEL_AR = {
    "critical": "حرجة", "high": "عالية", "medium": "متوسطة", "low": "منخفضة",
}
SEVERITY_COLOR = {
    "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309", "low": "#4b5563",
}


@dataclass
class ReportPaths:
    markdown_path: str
    html_path: str


class ReportGenerator:
    def __init__(self, memory: AgentMemory):
        self.memory = memory

    # ---------- تجميع البيانات ----------
    def _collect(self, scan_id: int) -> dict:
        meta = self.memory.get_scan_meta(scan_id)
        if meta is None:
            raise ValueError(f"لا يوجد فحص بالمعرّف {scan_id}")
        findings = self.memory.get_scan_findings(scan_id)

        confirmed = [f for f in findings if f["llm_verdict"] != "false_positive"]
        false_positives = [f for f in findings if f["llm_verdict"] == "false_positive"]

        by_severity: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in confirmed:
            sev = (f["severity"] or "low").lower()
            if sev in by_severity:
                by_severity[sev] += 1

        return {
            "repo": meta["repo"],
            "created_at": datetime.fromtimestamp(meta["created_at"], tz=timezone.utc),
            "scan_id": scan_id,
            "total": len(findings),
            "confirmed": confirmed,
            "false_positives": false_positives,
            "by_severity": by_severity,
        }

    # ---------- Markdown ----------
    def render_markdown(self, scan_id: int) -> str:
        d = self._collect(scan_id)
        lines: list[str] = []
        lines.append(f"# تقرير فحص أمني — {d['repo']}")
        lines.append("")
        lines.append(f"- **رقم الفحص:** {d['scan_id']}")
        lines.append(f"- **تاريخ الفحص (UTC):** {d['created_at'].strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"- **إجمالي البلاغات:** {d['total']}")
        lines.append(f"- **ثغرات حقيقية:** {len(d['confirmed'])}  |  **بلاغات خاطئة (تم تجاهلها):** {len(d['false_positives'])}")
        lines.append("")
        lines.append("## ملخص حسب الخطورة")
        lines.append("")
        lines.append("| الخطورة | العدد |")
        lines.append("|---|---|")
        for sev in SEVERITY_ORDER:
            lines.append(f"| {SEVERITY_LABEL_AR[sev]} ({sev}) | {d['by_severity'][sev]} |")
        lines.append("")

        if d["confirmed"]:
            lines.append("## الثغرات المؤكدة والإصلاحات المقترحة")
            lines.append("")
            for f in d["confirmed"]:
                conf_pct = round((f["llm_confidence"] or 0) * 100)
                lines.append(f"### 🔴 `{f['rule_id']}` — {f['target']} ({SEVERITY_LABEL_AR.get(f['severity'], f['severity'])})")
                lines.append("")
                lines.append(f"**الثقة:** {conf_pct}%")
                if f.get("pr_url"):
                    lines.append(f"  |  **Pull Request:** [{f['pr_url']}]({f['pr_url']})")
                lines.append("")
                lines.append(f"**الوصف:** {f['description']}")
                lines.append("")
                if f.get("remediation_code"):
                    lang = f.get("language") or ""
                    lines.append(f"**الإصلاح المقترح** (`{f.get('patch_type') or 'code'}`):")
                    lines.append("")
                    lines.append(f"```{lang}")
                    lines.append(f["remediation_code"].rstrip())
                    lines.append("```")
                lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("## لا توجد ثغرات حقيقية مؤكدة في هذا الفحص ✅")
            lines.append("")

        if d["false_positives"]:
            lines.append("## بلاغات صُنِّفت كـ False Positive (تم تجاهلها)")
            lines.append("")
            for f in d["false_positives"]:
                lines.append(f"- `{f['rule_id']}` على `{f['target']}` — {f['description']}")
            lines.append("")

        lines.append("---")
        lines.append("*تم توليد هذا التقرير تلقائياً بواسطة DevSecOps AI Agent.*")
        return "\n".join(lines)

    # ---------- HTML ----------
    def render_html(self, scan_id: int) -> str:
        d = self._collect(scan_id)
        e = html.escape

        rows_severity = "".join(
            f"<tr><td>{SEVERITY_LABEL_AR[s]} ({s})</td><td>{d['by_severity'][s]}</td></tr>"
            for s in SEVERITY_ORDER
        )

        def finding_block(f: dict) -> str:
            conf_pct = round((f["llm_confidence"] or 0) * 100)
            color = SEVERITY_COLOR.get(f["severity"], "#4b5563")
            pr_html = (
                f'<p><strong>Pull Request:</strong> <a href="{e(f["pr_url"])}" target="_blank">{e(f["pr_url"])}</a></p>'
                if f.get("pr_url") else ""
            )
            code_html = ""
            if f.get("remediation_code"):
                code_html = (
                    f'<p><strong>الإصلاح المقترح</strong> '
                    f'(<code>{e(f.get("patch_type") or "code")}</code>):</p>'
                    f'<pre><code>{e(f["remediation_code"])}</code></pre>'
                )
            return f"""
            <div class="finding" style="border-left:4px solid {color};">
              <h3>{e(f['rule_id'])} — {e(f['target'])}
                <span class="badge" style="background:{color};">{e(SEVERITY_LABEL_AR.get(f['severity'], f['severity']))}</span>
              </h3>
              <p><strong>الثقة:</strong> {conf_pct}%</p>
              {pr_html}
              <p><strong>الوصف:</strong> {e(f['description'])}</p>
              {code_html}
            </div>"""

        confirmed_html = "".join(finding_block(f) for f in d["confirmed"]) or \
            '<p class="ok">✅ لا توجد ثغرات حقيقية مؤكدة في هذا الفحص.</p>'

        fp_html = ""
        if d["false_positives"]:
            items = "".join(
                f"<li><code>{e(f['rule_id'])}</code> على <code>{e(f['target'])}</code> — {e(f['description'])}</li>"
                for f in d["false_positives"]
            )
            fp_html = f"<h2>بلاغات صُنِّفت كـ False Positive</h2><ul>{items}</ul>"

        return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<title>تقرير أمني — {e(d['repo'])}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Tahoma, sans-serif; max-width: 900px;
         margin: 2rem auto; padding: 0 1rem; background:#f9fafb; color:#111827; }}
  h1 {{ border-bottom: 2px solid #111827; padding-bottom: .5rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #d1d5db; padding: .5rem .75rem; text-align: right; }}
  th {{ background: #111827; color: #fff; }}
  .finding {{ background:#fff; border-radius:6px; padding:1rem 1.25rem; margin:1rem 0;
              box-shadow:0 1px 3px rgba(0,0,0,.08); }}
  .badge {{ color:#fff; padding:2px 10px; border-radius:999px; font-size:.8rem; margin-inline-start:.5rem; }}
  pre {{ background:#0f172a; color:#e2e8f0; padding:1rem; border-radius:6px; overflow-x:auto; direction:ltr; text-align:left; }}
  code {{ font-family: "SF Mono", Consolas, monospace; }}
  .ok {{ color:#15803d; font-weight:bold; }}
  footer {{ margin-top:2rem; color:#6b7280; font-size:.85rem; text-align:center; }}
</style>
</head>
<body>
  <h1>تقرير فحص أمني — {e(d['repo'])}</h1>
  <p><strong>رقم الفحص:</strong> {d['scan_id']} &nbsp; | &nbsp;
     <strong>التاريخ (UTC):</strong> {d['created_at'].strftime('%Y-%m-%d %H:%M')}</p>
  <p><strong>إجمالي البلاغات:</strong> {d['total']} &nbsp; | &nbsp;
     <strong>ثغرات حقيقية:</strong> {len(d['confirmed'])} &nbsp; | &nbsp;
     <strong>بلاغات خاطئة:</strong> {len(d['false_positives'])}</p>

  <h2>ملخص حسب الخطورة</h2>
  <table><tr><th>الخطورة</th><th>العدد</th></tr>{rows_severity}</table>

  <h2>الثغرات المؤكدة والإصلاحات المقترحة</h2>
  {confirmed_html}

  {fp_html}

  <footer>تم توليد هذا التقرير تلقائياً بواسطة DevSecOps AI Agent.</footer>
</body>
</html>"""

    # ---------- حفظ ----------
    def generate(self, scan_id: int, output_dir: str = "reports") -> ReportPaths:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        meta = self.memory.get_scan_meta(scan_id)
        repo_slug = meta["repo"].replace("/", "_") if meta else "unknown"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base = f"{repo_slug}_scan{scan_id}_{ts}"

        md_path = out / f"{base}.md"
        html_path = out / f"{base}.html"

        md_path.write_text(self.render_markdown(scan_id), encoding="utf-8")
        html_path.write_text(self.render_html(scan_id), encoding="utf-8")

        logger.info("تم حفظ التقرير: %s و %s", md_path, html_path)
        return ReportPaths(markdown_path=str(md_path), html_path=str(html_path))
