from miniapp_scanner.engine.taint_analyzer import TaintAnalyzer


def _analyzer():
    cfg = {
        "sources": [
            {"name": "onLoad", "taint_params": True},
            {"name": "wx.getStorageSync", "taint_returns": True},
        ],
        "sinks": [
            {"name": "eval", "dangerous_arg": [0], "severity": "high"},
            {"name": "wx.request", "dangerous_arg": [0, 1], "severity": "medium"},
        ],
        "member_sinks": [
            {"member": "innerHTML", "severity": "high"},
        ],
        "sanitizers": [{"name": "encodeURIComponent"}],
    }
    return TaintAnalyzer(cfg)


def test_simple_taint_source_to_eval():
    code = """
    Page({
      onLoad(options) {
        const id = options.id;
        eval(id);
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert any(f["rule_id"] == "TAINT-eval" for f in findings)


def test_alias_chain_still_tainted():
    code = """
    Page({
      onLoad(options) {
        const a = options.url;
        const b = a;
        const c = b;
        eval(c);
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert any(f["rule_id"] == "TAINT-eval" for f in findings)


def test_sanitizer_breaks_taint():
    code = """
    Page({
      onLoad(options) {
        const id = options.id;
        const safe = encodeURIComponent(id);
        eval(safe);
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert not any(f["rule_id"] == "TAINT-eval" for f in findings)