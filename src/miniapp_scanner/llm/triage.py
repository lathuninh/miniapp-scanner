import json
from typing import Dict
from .client import LLMClient


SYSTEM_PROMPT = """你是一名资深小程序安全审计专家，正在对静态分析工具的报警做二次研判。
判断报警是真阳性（TP）、假阳性（FP）还是无法确定（UNCERTAIN）。
输出必须严格为 JSON，不要任何额外文字或 Markdown 代码块。"""


class LLMTriager:
    def __init__(self, client: LLMClient):
        self.client = client
        self.cache: Dict[str, Dict] = {}

    def triage(self, finding: Dict) -> Dict:
        key = f"{finding['rule_id']}|{finding['file']}|{finding['line']}"
        if key in self.cache:
            return self.cache[key]
        try:
            raw = self.client.chat(SYSTEM_PROMPT, self._prompt(finding),
                                   max_tokens=400, temperature=0.1)
            result = self._parse(raw)
        except Exception as e:
            result = {"verdict": "UNCERTAIN", "confidence": 0,
                      "reason": f"LLM 调用失败: {e}", "fix": ""}
        self.cache[key] = result
        return result

    @staticmethod
    def _prompt(f: Dict) -> str:
        trace = f.get("trace") or []
        trace_text = "\n".join(f"  → {t}" for t in trace) if trace else "  （无传播路径）"
        return f"""【规则】{f['rule_name']} ({f['rule_id']})
【描述】{f['description']}
【位置】{f['file']}:{f['line']}
【代码片段】{f['code']}
【污点路径】
{trace_text}

请输出 JSON：
{{"verdict":"TP|FP|UNCERTAIN","confidence":0-100,"reason":"简洁理由","fix":"修复建议"}}"""

    @staticmethod
    def _parse(text: str) -> Dict:
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        s, e = text.find("{"), text.rfind("}")
        if s >= 0 and e > s:
            text = text[s:e + 1]
        try:
            d = json.loads(text)
            return {
                "verdict": str(d.get("verdict", "UNCERTAIN")).upper(),
                "confidence": int(d.get("confidence", 0)),
                "reason": d.get("reason", ""),
                "fix": d.get("fix", ""),
            }
        except Exception:
            return {"verdict": "UNCERTAIN", "confidence": 0,
                    "reason": "LLM 返回格式无法解析", "fix": ""}