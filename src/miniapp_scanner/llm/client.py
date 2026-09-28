import json
import urllib.request
from typing import Optional

from ..config import get_llm_config


class LLMClient:
    def __init__(self, api_key: Optional[str] = None,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 profile: Optional[str] = None,
                 timeout: int = 60):
        cfg = get_llm_config(profile=profile)
        self.api_key = api_key or cfg.get("api_key", "")
        self.base_url = (base_url or cfg.get("base_url",
                          "https://api.openai.com/v1")).rstrip("/")
        self.model = model or cfg.get("model", "gpt-4o-mini")
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.api_key)

    def chat(self, system: str, user: str,
             max_tokens: int = 1500, temperature: float = 0.2) -> str:
        if not self.available():
            raise RuntimeError("LLM 未配置：请设置环境变量 LLM_API_KEY")
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"]