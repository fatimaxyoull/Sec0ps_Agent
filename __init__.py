"""
scanners/
---------
حزمة سكانرات فحص أمني ثابت (Static Analysis) — كل سكانر يُنتج قائمة
بلاغات بنفس صيغة تقرير الفحص المستخدمة في agent.py:

    {"findings": [{"rule_id": ..., "target": ..., "severity": ...,
                    "description": ..., "raw_context": ...}, ...]}

بحيث تتدفق نتائجه مباشرة إلى SecurityAnalyzer / LLMRouter دون أي
تحويل إضافي — أي سكانر جديد تضيفه هنا يصبح متوافقاً تلقائياً مع بقية
الـ Agent (الذاكرة، التقارير، فتح Pull Requests) بمجرد اتباعه نفس الصيغة.
"""

from .rce_scanner import RCEScanner, scan_files, scan_directory

__all__ = ["RCEScanner", "scan_files", "scan_directory"]
