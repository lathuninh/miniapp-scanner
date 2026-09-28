from typing import Dict, List
from .client import LLMClient


SYSTEM_PROMPT = """你是一名资深小程序安全顾问。基于扫描和研判结果，生成专业、精炼、
可落地执行的中文安全报告，使用 Markdown 格式。"""


class LLMReporter:
    def __init__(self, client: LLMClient):
        self.client = client

    def generate(self, report: Dict, triage_map: Dict) -> str:
        s = report["summary"]
        kept = []
        for f in report["findings"]:
            key = f"{f['rule_id']}|{f['file']}|{f['line']}"
            tr = triage_map.get(key, {})
            if tr.get("verdict") == "FP":
                continue
            kept.append((f, tr))
        kept.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x[0]["severity"], 9))
        kept = kept[:20]

        lines = []
        for i, (f, tr) in enumerate(kept, 1):
            trace = " → ".join(f.get("trace") or []) or "—"
            lines.append(
                f"{i}. [{f['severity'].upper()}] {f['rule_name']} ({f['file']}:{f['line']})\n"
                f"   - 说明：{f['description']}\n"
                f"   - 污点路径：{trace}\n"
                f"   - 研判：{tr.get('verdict','?')}（置信度 {tr.get('confidence',0)}）— {tr.get('reason','')}\n"
                f"   - 建议：{tr.get('fix') or f['suggestion']}"
            )
        findings_text = "\n".join(lines) if lines else "（无真阳性问题）"

        user = f"""【扫描概要】
- 目标：{report['target']}
- 文件数：{report['files_scanned']}，代码行数：{report['lines_scanned']}
- 原始报警：{s['total']} 条（高 {s['high']} / 中 {s['medium']} / 低 {s['low']}）

【重点问题】
{findings_text}

请按以下结构输出 Markdown 中文报告：

# 一、执行摘要
# 二、风险评级
# 三、重点问题分析
# 四、分阶段修复方案
- 🔥 紧急（24h）
- ⚡ 短期（1 周）
- 📅 中期（1 月）
# 五、代码修复示例
"""
        return self.client.chat(SYSTEM_PROMPT, user, max_tokens=3000, temperature=0.3)