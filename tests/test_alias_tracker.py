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

def test_obj_prop_via_alias():
    """obj.url 通过别名 alias.url 访问"""
    t = AliasTracker()
    t.record_prop("obj", "url", ["from-input"])
    t.record_alias("alias", "obj")
    assert t.get_prop("alias", "url") == ["from-input"]


def test_clear_taint_on_rep():
    """清除污染时应该清代表元"""
    t = AliasTracker()
    t.set_taint("x", ["p"])
    t.clear_taint("x")
    assert t.get_taint("x") is None


def test_snapshot_restore():
    """快照/恢复功能"""
    t = AliasTracker()
    t.set_taint("x", ["p"])
    snap = t.snapshot()
    t.set_taint("y", ["q"])
    t.restore(snap)
    assert t.get_taint("y") is None
    assert t.get_taint("x") == ["p"]