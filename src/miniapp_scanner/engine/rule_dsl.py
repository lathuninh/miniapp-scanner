"""规则 DSL 求值器。"""
import re
from typing import Any, Dict, List, Optional


class DSLContext:
    def __init__(self, node: Dict, file_path: str, taint_lookup, line: int):
        self.node = node
        self.file_path = file_path
        self.taint_lookup = taint_lookup
        self.line = line


class RuleDSL:
    def __init__(self, rule: Dict):
        self.rule = rule
        self.id = rule["id"]
        self.info = rule.get("info", {})
        self.dsl = rule.get("dsl", {})

    def match(self, node: Dict, file_path: str, taint_lookup=None) -> Optional[Dict]:
        target = self.dsl.get("node")
        if target and node.get("type") != target:
            return None
        line = node.get("loc", {}).get("start", {}).get("line", 0)
        ctx = DSLContext(node, file_path, taint_lookup or (lambda _: False), line)
        conds = self.dsl.get("conditions", [])
        if not self._eval_all(conds, ctx):
            return None
        return {
            "rule_id": self.id,
            "rule_name": self.info.get("name", self.id),
            "severity": self.info.get("severity", "medium"),
            "file": file_path,
            "line": line,
            "code": self.dsl.get("code", f"<{node.get('type')}>"),
            "description": self.info.get("description", ""),
            "suggestion": self.info.get("suggestion", ""),
            "engine": "dsl",
            "trace": [],
        }

    def _eval_all(self, conds: List[Dict], ctx: DSLContext) -> bool:
        return all(self._eval(c, ctx) for c in conds)

    def _eval(self, cond: Dict, ctx: DSLContext) -> bool:
        if not isinstance(cond, dict):
            return False
        if "and" in cond:
            return all(self._eval(c, ctx) for c in cond["and"])
        if "or" in cond:
            return any(self._eval(c, ctx) for c in cond["or"])
        if "not" in cond:
            return not self._eval(cond["not"], ctx)
        if "eq" in cond:
            a, b = cond["eq"]
            return self._resolve(a, ctx) == self._resolve(b, ctx)
        if "neq" in cond:
            a, b = cond["neq"]
            return self._resolve(a, ctx) != self._resolve(b, ctx)
        if "match" in cond:
            path, regex = cond["match"]
            v = self._resolve(path, ctx)
            return bool(v is not None and re.search(regex, str(v)))
        if "in" in cond:
            path, values = cond["in"]
            return self._resolve(path, ctx) in values
        if "exists" in cond:
            return self._resolve(cond["exists"][0], ctx) is not None
        if "file_match" in cond:
            return bool(re.search(cond["file_match"][0], ctx.file_path))
        if "tainted" in cond:
            expr = self._resolve_raw(cond["tainted"][0], ctx)
            return ctx.taint_lookup(expr)
        if "arg_tainted" in cond:
            idx = cond["arg_tainted"][0]
            args = ctx.node.get("arguments", [])
            return idx < len(args) and ctx.taint_lookup(args[idx])
        return False

    def _resolve(self, path, ctx: DSLContext):
        if not isinstance(path, str):
            return path
        if path.startswith("@"):
            return path[1:]
        # 不含点号的字符串，视为字面量（如 "eval"、"foo"），不解析为路径
        if "." not in path:
            return path
        cur: Any = ctx.node
        for p in path.split("."):
            if cur is None:
                return None
            if isinstance(cur, list):
                try:
                    cur = cur[int(p)]
                except (ValueError, IndexError):
                    return None
            elif isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return None
        return cur

    def _resolve_raw(self, path, ctx: DSLContext):
        if not isinstance(path, str):
            return path
        cur: Any = ctx.node
        for p in path.split("."):
            if cur is None:
                return None
            if isinstance(cur, list):
                try:
                    cur = cur[int(p)]
                except (ValueError, IndexError):
                    return None
            elif isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return None
        return cur

    @classmethod
    def load_all(cls, yaml_data: Dict) -> List["RuleDSL"]:
        return [cls(r) for r in yaml_data.get("rules", [])]