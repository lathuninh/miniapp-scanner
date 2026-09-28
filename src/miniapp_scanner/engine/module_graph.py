"""跨文件模块依赖图。"""
import os
import esprima
from pathlib import Path
from typing import Dict, Optional


class ModuleGraph:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.modules: Dict[str, Dict] = {}
        self._build()

    def _build(self):
        for js in self.root.rglob("*.js"):
            if "node_modules" in js.parts:
                continue
            rel = str(js.relative_to(self.root)).replace("\\", "/")
            try:
                src = js.read_text(encoding="utf-8", errors="ignore")
                tree = esprima.parseScript(
                    src, {"loc": True, "tolerant": True}
                ).toDict()
            except Exception:
                continue
            self.modules[rel] = self._extract(rel, tree)

    def _extract(self, rel: str, tree: Dict) -> Dict:
        info = {"imports": {}, "exports": {}, "functions": {}, "path": rel}
        for node in self._iter(tree):
            if node.get("type") == "FunctionDeclaration" and node.get("id"):
                info["functions"][node["id"]["name"]] = node
        for node in self._iter(tree):
            if node.get("type") == "VariableDeclaration":
                for d in node.get("declarations", []):
                    self._handle_import(d, rel, info)
            elif node.get("type") == "AssignmentExpression":
                self._handle_export(node, info)
        return info

    def _handle_import(self, decl: Dict, rel: str, info: Dict):
        init = decl.get("init")
        if not init or init.get("type") != "CallExpression":
            return
        if init.get("callee", {}).get("name") != "require":
            return
        args = init.get("arguments", [])
        if not args or args[0].get("type") != "Literal":
            return
        target_path = self._resolve(rel, args[0].get("value", ""))
        if not target_path:
            return
        lhs = decl.get("id", {})
        if lhs.get("type") == "ObjectPattern":
            for p in lhs.get("properties", []):
                local = p.get("value", {}).get("name")
                orig = p.get("key", {}).get("name")
                if local:
                    info["imports"][local] = (target_path, orig)
        elif lhs.get("type") == "Identifier":
            info["imports"][lhs["name"]] = (target_path, "*")

    def _handle_export(self, node: Dict, info: Dict):
        left, right = node.get("left", {}), node.get("right", {})
        if left.get("type") != "MemberExpression":
            return
        obj, prop = left.get("object", {}), left.get("property", {})
        if obj.get("name") == "module" and prop.get("name") == "exports":
            if right.get("type") == "ObjectExpression":
                for p in right.get("properties", []):
                    k = p.get("key", {}).get("name")
                    info["exports"][k] = self._resolve_value(p.get("value", {}), info)
        elif obj.get("name") == "exports":
            info["exports"][prop.get("name")] = self._resolve_value(right, info)

    def _resolve_value(self, v: Dict, info: Dict) -> Optional[Dict]:
        if v.get("type") == "Identifier":
            return info["functions"].get(v["name"])
        if v.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
            return v
        return None

    def _resolve(self, from_rel: str, target: str) -> Optional[str]:
        if not target.startswith("."):
            return None
        base = os.path.dirname(from_rel)
        p = os.path.normpath(os.path.join(base, target)).replace("\\", "/")
        for cand in (p, p + ".js", p + "/index.js"):
            if cand in self.modules:
                return cand
        return None

    def get_function(self, file_rel: str, export_name: str) -> Optional[Dict]:
        m = self.modules.get(file_rel)
        if not m:
            return None
        return m["exports"].get(export_name) or m["functions"].get(export_name)

    def get_imports(self, file_rel: str) -> Dict:
        m = self.modules.get(file_rel)
        return m["imports"] if m else {}

    @staticmethod
    def _iter(node):
        if isinstance(node, dict):
            yield node
            for v in node.values():
                yield from ModuleGraph._iter(v)
        elif isinstance(node, list):
            for it in node:
                yield from ModuleGraph._iter(it)