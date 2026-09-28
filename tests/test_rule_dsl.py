from miniapp_scanner.engine.js_parser import parse_js
from miniapp_scanner.engine.rule_dsl import RuleDSL


def _call_node(src):
    tree = parse_js(src)
    return tree["body"][0]["expression"]


def test_eq_callee_name():
    rule = RuleDSL({
        "id": "T1",
        "info": {"name": "t", "severity": "high"},
        "dsl": {
            "node": "CallExpression",
            "conditions": [
                {"or": [
                    {"eq": ["callee.name", "eval"]},
                    {"eq": ["callee.property.name", "eval"]},
                ]}
            ],
        },
    })
    assert rule.match(_call_node("eval(x);"), "a.js") is not None
    assert rule.match(_call_node("foo(x);"), "a.js") is None


def test_arg_tainted():
    rule = RuleDSL({
        "id": "T3",
        "info": {"name": "t", "severity": "high"},
        "dsl": {"node": "CallExpression",
                "conditions": [{"arg_tainted": [0]}]},
    })
    node = _call_node("eval(x);")
    assert rule.match(node, "a.js", taint_lookup=lambda _: True) is not None
    assert rule.match(node, "a.js", taint_lookup=lambda _: False) is None