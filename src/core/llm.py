"""MiMo LLM Client for Red Team Engine."""
import json
import logging
import httpx
from ..config import MIMO_API_URL, MIMO_MODEL, MIMO_MAX_TOKENS

logger = logging.getLogger("redteam.llm")


class MiMoLLM:
    def __init__(self):
        self.api_url = MIMO_API_URL
        self.model = MIMO_MODEL
        self.max_tokens = MIMO_MAX_TOKENS

    async def analyze(self, system_prompt: str, user_prompt: str) -> str:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    self.api_url,
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt}
                        ],
                        "max_tokens": self.max_tokens,
                        "temperature": 0.7,
                        "stream": False
                    }
                )
                data = resp.json()
                if "choices" in data and len(data["choices"]) > 0:
                    msg = data["choices"][0].get("message", {})
                    return msg.get("content", "")
                return ""
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return f"[LLM Error: {e}]"

    async def analyze_json(self, system_prompt: str, user_prompt: str) -> dict:
        raw = await self.analyze(system_prompt, user_prompt)
        try:
            if raw.startswith("```"):
                lines = raw.split("\n")
                lines = [l for l in lines if not l.startswith("```")]
                raw = "\n".join(lines)
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw, "parsed": False}
