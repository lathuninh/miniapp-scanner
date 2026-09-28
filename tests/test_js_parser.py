from miniapp_scanner.engine.js_parser import parse_js


def test_string_concat_folding():
    tree = parse_js('const x = "ev" + "al";')
    init = tree["body"][0]["declarations"][0]["init"]
    assert init["type"] == "Literal"
    assert init["value"] == "eval"


def test_template_literal_folding():
    tree = parse_js("const x = `abc`;")
    init = tree["body"][0]["declarations"][0]["init"]
    assert init["type"] == "Literal"
    assert init["value"] == "abc"


def test_computed_member_folding():
    tree = parse_js('window["eval"]("payload");')
    callee = tree["body"][0]["expression"]["callee"]
    assert callee["computed"] is False
    assert callee["property"]["name"] == "eval"


def test_invalid_input_returns_none():
    assert parse_js("function (") is None