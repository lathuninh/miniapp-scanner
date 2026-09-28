"""别名/指针分析：并查集 + 对象属性图。"""
from typing import Dict, List, Optional, Set


class UnionFind:
    def __init__(self):
        self.parent: Dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
            return x
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def group(self, x: str) -> Set[str]:
        rep = self.find(x)
        return {k for k in self.parent if self.find(k) == rep}


class AliasTracker:
    def __init__(self):
        self.uf = UnionFind()
        self.tainted: Dict[str, List[str]] = {}
        self.obj_props: Dict[str, List[str]] = {}

    def record_alias(self, lhs: str, rhs: str):
        self.uf.union(lhs, rhs)

    def set_taint(self, name: str, trace: List[str]):
        self.tainted[self.uf.find(name)] = list(trace)

    def get_taint(self, name: str) -> Optional[List[str]]:
        return self.tainted.get(self.uf.find(name))

    def clear_taint(self, name: str):
        self.tainted.pop(self.uf.find(name), None)

    def record_prop(self, obj: str, prop: str, trace: List[str]):
        for alias in self.uf.group(obj) | {obj}:
            self.obj_props[f"{alias}.{prop}"] = list(trace)

    def record_prop_alias(self, target: str, obj: str, prop: str):
        for alias in self.uf.group(obj) | {obj}:
            key = f"{alias}.{prop}"
            if key in self.obj_props:
                self.set_taint(target, self.obj_props[key] + [f"读取属性 {key}"])
                return

    def get_prop(self, obj: str, prop: str) -> Optional[List[str]]:
        for alias in self.uf.group(obj) | {obj}:
            key = f"{alias}.{prop}"
            if key in self.obj_props:
                return self.obj_props[key]
        return None

    def snapshot(self):
        return {
            "parent": dict(self.uf.parent),
            "tainted": {k: list(v) for k, v in self.tainted.items()},
            "obj_props": {k: list(v) for k, v in self.obj_props.items()},
        }

    def restore(self, snap):
        self.uf.parent = dict(snap["parent"])
        self.tainted = {k: list(v) for k, v in snap["tainted"].items()}
        self.obj_props = {k: list(v) for k, v in snap["obj_props"].items()}