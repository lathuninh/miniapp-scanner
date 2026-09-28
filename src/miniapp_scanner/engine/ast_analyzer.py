"""AST 规则 + DSL 规则求值。"""
from typing import Callable, Dict, List, Optional

from .js_parser import parse_js
from .rule_dsl import RuleDSL


class AstAnalyzer:
    def analyze(self, source: str, file_path: str, rules: List[Dict],
                dsl_rules: Optional[List[RuleDSL]] = None,
                taint_lookup: Optional[Callable] = None) -> List[Dict]:
        findings: List[Dict] = []
        tree = parse_js(source)
        if not tree:
            return findings

        for rule in rules:
            self._walk_ast(tree, file_path, rule, rule["check"]["ast_pattern"], findings)

        if dsl_rules:
            self._walk_dsl(tree, file_path, dsl_rules, taint_lookup or (lambda _: False), findings)

        return findings

    def _walk_ast(self, node, file_path: str, rule: Dict, pattern: Dict, out: List[Dict]):
        if not isinstance(node, dict):
            if isinstance(node, list):
                for n in node:
                    self._walk_ast(n, file_path, rule, pattern, out)
            return
        if self._match_node(node, pattern):
            line = node.get("loc", {}).get("start", {}).get("line", 0)
            out.append({
                "rule_id": rule["id"],
                "rule_name": rule["info"]["name"],
                "severity": rule["info"]["severity"],
                "file": file_path, "line": line,
                "code": self._snippet(node),
                "description": rule["info"]["description"],
                "suggestion": rule["info"]["suggestion"],
                "engine": "ast", "trace": [],
            })
        for v in node.values():
            self._walk_ast(v, file_path, rule, pattern, out)

    def _match_node(self, node: Dict, pattern: Dict) -> bool:
        if node.get("type") != pattern.get("node_type"):
            return False
        if "callee_object" in pattern:
            callee = node.get("callee", {})
            if not (callee.get("type") == "MemberExpression"
                    and callee.get("object", {}).get("name") == pattern["callee_object"]
                    and callee.get("property", {}).get("name") == pattern["callee_property"]):
                return False
        if "callee_name" in pattern:
            callee = node.get("callee", {})
            if not (callee.get("type") == pattern.get("callee_type", "Identifier")
                    and callee.get("name") == pattern["callee_name"]):
                return False
        if "key_name" in pattern:
            if node.get("key", {}).get("name") != pattern["key_name"]:
                return False
        if "left_property" in pattern:
            left = node.get("left", {})
            if not (left.get("type") == "MemberExpression"
                    and left.get("property", {}).get("name") == pattern["left_property"]):
                return False
        if "value_value" in pattern:
            if node.get("value", {}).get("value") != pattern["value_value"]:
                return False
        if "arg_contains_any" in pattern:
            kws = [k.lower() for k in pattern["arg_contains_any"]]
            arg_texts = []
            for a in node.get("arguments", []):
                if a.get("type") == "Literal":
                    arg_texts.append(str(a.get("value", "")))
                elif a.get("type") == "Identifier":
                    arg_texts.append(a.get("name", ""))
                elif a.get("type") == "MemberExpression":
                    arg_texts.append(str(a.get("property", {}).get("name", "")))
            joined = " ".join(arg_texts).lower()
            if not any(k in joined for k in kws):
                return False
        return True

    @staticmethod
    def _snippet(node: Dict) -> str:
        t = node.get("type")
        if t == "CallExpression":
            c = node.get("callee", {})
            if c.get("type") == "MemberExpression":
                return f"{c.get('object',{}).get('name','?')}." \
                       f"{c.get('property',{}).get('name','?')}(...)"
            return f"{c.get('name','?')}(...)"
        if t == "Property":
            return f"{node.get('key',{}).get('name','?')}: ..."
        if t == "AssignmentExpression":
            left = node.get("left", {})
            return f"{left.get('object',{}).get('name','?')}." \
                   f"{left.get('property',{}).get('name','?')} = ..."
        return t or "unknown"

    def _walk_dsl(self, node, file_path: str, dsl_rules: List[RuleDSL],
                  taint_lookup, out: List[Dict]):
        if not isinstance(node, dict):
            if isinstance(node, list):
                for n in node:
                    self._walk_dsl(n, file_path, dsl_rules, taint_lookup, out)
            return
        for rule in dsl_rules:
            hit = rule.match(node, file_path, taint_lookup=taint_lookup)
            if hit:
                key = (hit["rule_id"], hit["file"], hit["line"])
                if not any((f["rule_id"], f["file"], f["line"]) == key for f in out):
                    out.append(hit)
        for v in node.values():
            self._walk_dsl(v, file_path, dsl_rules, taint_lookup, out)