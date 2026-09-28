"""混淆代码预处理。"""
import re
from typing import Dict, List


class ObfuscationPreprocessor:
    HEX_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}")
    UNI_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")
    SINGLE_CHAR_VAR = re.compile(r"\b(?:var|let|const)\s+([a-zA-Z_$])\s*=")
    STRING_CONCAT = re.compile(r"""(['"])(.*?)\1\s*\+\s*(['"])(.*?)\3""")

    def __init__(self):
        self.stats: Dict[str, Dict] = {}

    def preprocess(self, source: str, file_path: str) -> str:
        signals = {
            "file": file_path,
            "hex_escapes": len(self.HEX_ESCAPE.findall(source)),
            "unicode_escapes": len(self.UNI_ESCAPE.findall(source)),
            "single_char_vars": len(self.SINGLE_CHAR_VAR.findall(source)),
            "string_concat": len(self.STRING_CONCAT.findall(source)),
        }
        signals["is_obfuscated"] = (
            signals["hex_escapes"] + signals["unicode_escapes"] >= 3
            or signals["single_char_vars"] >= 5
        )
        self.stats[file_path] = signals
        return source

    def is_obfuscated(self, file_path: str) -> bool:
        return self.stats.get(file_path, {}).get("is_obfuscated", False)

    def report(self) -> List[Dict]:
        return [v for v in self.stats.values() if v["is_obfuscated"]]