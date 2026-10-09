import json
from typing import Dict
from .client import LLMClient


SYSTEM_PROMPT = """你是一名资深微信小程序安全审计专家，正在对静态分析工具的报警做二次研判。
你的任务：判断报警是真阳性（TP）、假阳性（FP）还是无法确定（UNCERTAIN）。

【重要】小程序特有的攻击面：
1. 小程序只能跳转到内部页面（wx.navigateTo / wx.redirectTo），无法像 Web 一样跳转到外部域名
2. 但通过 URL 参数拼接，仍可能存在"参数注入"和"二级污点链"风险
3. wx.setStorageSync 里的 token 一旦被越狱设备读取，等于账户被接管（高危）
4. 用户输入 e.detail.value、e.currentTarget.dataset.* 都是可控的
5. 即使小程序框架会校验页面路径，拼接逻辑本身如果缺少 encodeURIComponent 仍有风险

【研判要点】
1. 代码是否真的会执行到危险逻辑（不是出现在注释、字符串、示例配置中）
2. 输入源是否真的可控（用户输入 vs 硬编码常量 vs 后端数据）
3. 是否已通过净化函数（encodeURIComponent、白名单校验、parseInt 等）
4. 触发条件在当前代码路径下是否可达
5. **对于真实存在但严重度较低的问题，应判为 TP 或 UNCERTAIN，不要因影响小就判为 FP**
6. **只有代码上下文明确表明"问题不成立"时，才判为 FP**

【输出格式】必须严格为 JSON，不要任何额外文字或 Markdown 代码块：
{
  "verdict": "TP|FP|UNCERTAIN",
  "confidence": 0-100,
  "reason": "50字内的简洁理由",
  "fix": "80字内可操作的修复建议"
}"""


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