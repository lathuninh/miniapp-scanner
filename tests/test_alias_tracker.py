from miniapp_scanner.engine.alias_tracker import AliasTracker


def test_union_find_basic():
    t = AliasTracker()
    t.record_alias("a", "b")
    t.record_alias("b", "c")
    assert t.uf.find("a") == t.uf.find("c")
    assert {"a", "b", "c"} <= t.uf.group("a")


def test_taint_via_alias():
    t = AliasTracker()
    t.record_alias("a", "b")       # 先建立别名
    t.record_alias("b", "c")
    t.set_taint("a", ["origin"])   # 再污染
    assert t.get_taint("c") == ["origin"]


def test_obj_prop_tracking():
    t = AliasTracker()
    t.record_prop("obj", "url", ["from-input"])
    assert t.get_prop("obj", "url") == ["from-input"]