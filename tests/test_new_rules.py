"""测试新增的 3 条规则：支付、定位、剪贴板"""
from miniapp_scanner.engine.taint_analyzer import TaintAnalyzer


def _analyzer():
    cfg = {
        "sources": [
            {"name": "onLoad", "taint_params": True},
            {"member": "e.detail.value"},
        ],
        "sinks": [
            {"name": "wx.requestPayment", "dangerous_arg": [0], "severity": "high"},
            {"name": "wx.openLocation", "dangerous_arg": [0], "severity": "medium"},
            {"name": "wx.setClipboardData", "dangerous_arg": [0], "severity": "low"},
        ],
        "member_sinks": [],
        "sanitizers": [{"name": "encodeURIComponent"}],
    }
    return TaintAnalyzer(cfg)


def test_request_payment_with_taint():
    """支付金额被污染 → 报警"""
    code = """
    Page({
      onPay(e) {
        const amount = e.detail.value.amount;
        wx.requestPayment({ totalFee: amount });
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert any(f["rule_id"] == "TAINT-wx.requestPayment" for f in findings)


def test_open_location_with_taint():
    """定位坐标被污染 → 报警"""
    code = """
    Page({
      onLocate(e) {
        const lat = e.detail.value.latitude;
        wx.openLocation({ latitude: lat });
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert any(f["rule_id"] == "TAINT-wx.openLocation" for f in findings)


def test_set_clipboard_with_taint():
    """剪贴板内容被污染 → 报警"""
    code = """
    Page({
      onCopy(e) {
        const data = e.detail.value.content;
        wx.setClipboardData({ data: data });
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert any(f["rule_id"] == "TAINT-wx.setClipboardData" for f in findings)


def test_request_payment_with_static_value():
    """支付金额是静态值 → 不报警"""
    code = """
    Page({
      onPay() {
        wx.requestPayment({ totalFee: 100 });
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert not any(f["rule_id"] == "TAINT-wx.requestPayment" for f in findings)


def test_set_clipboard_with_sanitized():
    """剪贴板内容经过净化 → 不报警"""
    code = """
    Page({
      onCopy(e) {
        const data = encodeURIComponent(e.detail.value.content);
        wx.setClipboardData({ data: data });
      }
    });
    """
    findings = _analyzer().analyze(code, "test.js")
    assert not any(f["rule_id"] == "TAINT-wx.setClipboardData" for f in findings)