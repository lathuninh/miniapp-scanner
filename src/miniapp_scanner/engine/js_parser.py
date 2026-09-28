"""统一的 JS 解析入口 + 常量折叠。"""
import esprima
from typing import Optional, Dict


def parse_js(source: str) -> Optional[Dict]:
    try:
        tree = esprima.parseScript(source, {"loc": True, "tolerant": True})
        if hasattr(tree, "toDict"):
            tree = tree.toDict()
    except Exception:
        return None
    if not isinstance(tree, dict):
        return None
    return fold_constants(tree)


def fold_constants(node):
    if isinstance(node, list):
        return [fold_constants(n) for n in node]
    if not isinstance(node, dict):
        return node

    for k, v in list(node.items()):
        node[k] = fold_constants(v)

    t = node.get("type")

    if t == "BinaryExpression" and node.get("operator") == "+":
        l, r = node.get("left"), node.get("right")
        if (l and l.get("type") == "Literal" and isinstance(l.get("value"), str)
                and r and r.get("type") == "Literal" and isinstance(r.get("value"), str)):
            return {
                "type": "Literal",
                "value": l["value"] + r["value"],
                "loc": node.get("loc"),
                "_folded": True,
            }

    if t == "TemplateLiteral" and not node.get("expressions"):
        text = "".join(q.get("value", {}).get("cooked", "")
                       for q in node.get("quasis", []))
        return {
            "type": "Literal", "value": text,
            "loc": node.get("loc"), "_folded": True,
        }

    if t == "MemberExpression" and node.get("computed"):
        prop = node.get("property")
        if prop and prop.get("type") == "Literal" and isinstance(prop.get("value"), str):
            node["computed"] = False
            node["property"] = {"type": "Identifier", "name": prop["value"],
                                "loc": prop.get("loc")}
            node["_folded"] = True

    return node