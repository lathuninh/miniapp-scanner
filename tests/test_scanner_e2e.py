from miniapp_scanner.scanner import Scanner


def test_scanner_detects_hardcoded_secrets(sample_dir):
    scanner = Scanner()
    report = scanner.scan(str(sample_dir))
    rules_hit = {f["rule_id"] for f in report["findings"]}
    assert "SEC-001" in rules_hit
    assert "SEC-003" in rules_hit
    assert "SEC-101" in rules_hit


def test_scanner_summary_keys(sample_dir):
    scanner = Scanner()
    report = scanner.scan(str(sample_dir))
    assert report["summary"]["total"] == len(report["findings"])
    for k in ("high", "medium", "low", "total"):
        assert k in report["summary"]