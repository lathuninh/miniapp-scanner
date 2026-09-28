"""污点分析引擎（别名感知 + 跨文件 + 控制流敏感）。"""
from typing import Dict, List, Optional

from .js_parser import parse_js
from .alias_tracker import AliasTracker


class TaintAnalyzer:
    MAX_CROSS_FILE_DEPTH = 5

    def __init__(self, config: Dict, registry=None):
        self.sources = config.get("sources", [])
        self.sinks = config.get("sinks", [])
        self.member_sinks = config.get("member_sinks", [])
        self.sanitizers = config.get("sanitizers", [])
        self.registry = registry
        self.aliases = AliasTracker()
        self.constants: Dict[str, object] = {}
        self.findings: List[Dict] = []
        self.current_file = ""
        self._call_depth = 0
        self._returned = False

    def analyze(self, code: str, file_path: str) -> List[Dict]:
        self.aliases = AliasTracker()
        self.constants, self.findings = {}, []
        self.current_file = file_path
        self._call_depth = 0
        self._returned = False
        tree = parse_js(code)
        if not tree:
            return []
        self._walk_scope(tree, file_path)
        return self.findings

    def _walk_scope(self, node, file_path):
        snap_a = self.aliases.snapshot()
        snap_c = dict(self.constants)
        body = node.get("body", [])
        if isinstance(body, dict):
            body = [body]
        for stmt in body:
            self._exec_stmt(stmt, file_path)
        self.aliases.restore(snap_a)
        self.constants = snap_c

    def _exec_stmt(self, node, file_path):
        if not node:
            return
        t = node.get("type")
        if t == "VariableDeclaration":
            for d in node.get("declarations", []):
                self._handle_var_decl(d, node.get("kind", "var"), file_path)
        elif t == "ExpressionStatement":
            self._eval_expr(node.get("expression", {}), file_path)
        elif t == "FunctionDeclaration":
            self._handle_function_like(node, node.get("id", {}).get("name", ""), file_path)
        elif t == "BlockStatement":
            for s in node.get("body", []):
                self._exec_stmt(s, file_path)
        elif t == "IfStatement":
            self._handle_if(node, file_path)
        elif t in ("ForStatement", "WhileStatement", "DoWhileStatement"):
            self._exec_stmt(node.get("body"), file_path)
        elif t == "ReturnStatement":
            self._eval_expr(node.get("argument"), file_path)
            self._returned = True
        elif t == "TryStatement":
            self._exec_stmt(node.get("block"), file_path)
            if node.get("handler"):
                self._exec_stmt(node["handler"].get("body"), file_path)

    def _handle_if(self, node, file_path):
        cond = self._eval_condition(node.get("test"))
        if cond is True:
            self._exec_stmt(node.get("consequent"), file_path)
        elif cond is False:
            if node.get("alternate"):
                self._exec_stmt(node["alternate"], file_path)
        else:
            self._exec_stmt(node.get("consequent"), file_path)
            if node.get("alternate"):
                self._exec_stmt(node["alternate"], file_path)

    def _eval_condition(self, test) -> Optional[bool]:
        if not test:
            return None
        t = test.get("type")
        if t == "Literal":
            return bool(test.get("value"))
        if t == "Identifier":
            v = self.constants.get(test.get("name"))
            return None if v is None else bool(v)
        if t == "UnaryExpression" and test.get("operator") == "!":
            inner = self._eval_condition(test.get("argument"))
            return None if inner is None else (not inner)
        if t == "BinaryExpression":
            l, r = self._eval_const(test.get("left")), self._eval_const(test.get("right"))
            if l is None or r is None:
                return None
            op = test.get("operator")
            try:
                return {"===": l == r, "==": l == r, "!==": l != r, "!=": l != r,
                        "<": l < r, ">": l > r, "<=": l <= r, ">=": l >= r}.get(op)
            except Exception:
                return None
        return None

    def _eval_const(self, node):
        if not node:
            return None
        if node.get("type") == "Literal":
            return node.get("value")
        if node.get("type") == "Identifier":
            return self.constants.get(node.get("name"))
        return None

    def _handle_var_decl(self, decl, kind, file_path):
        name = decl.get("id", {}).get("name")
        init = decl.get("init")
        if not name:
            return

        if init and kind == "const" and init.get("type") == "Literal":
            self.constants[name] = init.get("value")
        else:
            self.constants.pop(name, None)

        if init and kind == "const":
            it = init.get("type")
            if it == "Identifier":
                self.aliases.record_alias(name, init["name"])
            elif it == "MemberExpression":
                obj = self._member_name(init.get("object"))
                prop = self._member_name(init.get("property"))
                if obj and prop and obj != "this":
                    self.aliases.record_prop_alias(name, obj, prop)
            elif it == "ObjectExpression":
                for p in init.get("properties", []):
                    if p.get("type") != "Property":
                        continue
                    key = self._member_name(p.get("key"))
                    val = p.get("value", {})
                    if val.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
                        self._handle_function_like(val, key, file_path)
                    else:
                        tr = self._eval_expr(val, file_path)
                        if key and tr:
                            self.aliases.record_prop(name, key, tr)

        if init:
            tr = self._eval_expr(init, file_path)
            if tr:
                self.aliases.set_taint(name, tr + [f"存入变量 {name}"])
            else:
                self.aliases.clear_taint(name)
        else:
            self.aliases.clear_taint(name)

    def _handle_function_like(self, node, name, file_path):
        snap_a = self.aliases.snapshot()
        snap_c = dict(self.constants)
        saved_ret = self._returned
        self._returned = False

        for p in node.get("params", []):
            pname = p.get("name")
            if pname and name and self._is_source_param(name):
                self.aliases.set_taint(pname, [f"{name} 的参数 {pname}（用户可控）"])

        body = node.get("body", {})
        if body.get("type") == "BlockStatement":
            for s in body.get("body", []):
                if self._returned:
                    break
                self._exec_stmt(s, file_path)

        self.aliases.restore(snap_a)
        self.constants = snap_c
        self._returned = saved_ret

    def _eval_expr(self, node, file_path) -> Optional[List[str]]:
        if not node:
            return None
        t = node.get("type")

        if t == "Literal":
            return None
        if t == "Identifier":
            return self.aliases.get_taint(node.get("name"))
        if t == "MemberExpression":
            full = self._member_name(node)
            if self._is_source_member(full):
                return [f"读取 {full}（用户可控）"]
            obj = self._member_name(node.get("object"))
            prop = self._member_name(node.get("property"))
            if obj and prop:
                tr = self.aliases.get_prop(obj, prop)
                if tr:
                    return tr + [f"读取属性 {obj}.{prop}"]
            return self._eval_expr(node.get("object"), file_path)
        if t == "CallExpression":
            return self._eval_call(node, file_path)
        if t == "TemplateLiteral":
            traces = []
            for e in node.get("expressions", []):
                tr = self._eval_expr(e, file_path)
                if tr:
                    traces.extend(tr)
            return traces + ["模板字符串拼接"] if traces else None
        if t == "BinaryExpression":
            if node.get("operator") == "+":
                l = self._eval_expr(node.get("left"), file_path)
                r = self._eval_expr(node.get("right"), file_path)
                if l or r:
                    return (l or []) + (r or []) + ["字符串拼接"]
            return None
        if t == "ConditionalExpression":
            return (self._eval_expr(node.get("consequent"), file_path)
                    or self._eval_expr(node.get("alternate"), file_path))
        if t == "AssignmentExpression":
            return self._handle_assign(node, file_path)
        if t == "ObjectExpression":
            for p in node.get("properties", []):
                if p.get("type") != "Property":
                    continue
                val = p.get("value", {})
                if val.get("type") in ("FunctionExpression", "ArrowFunctionExpression"):
                    self._handle_function_like(val, p.get("key", {}).get("name", ""), file_path)
                    continue
                tr = self._eval_expr(val, file_path)
                if tr:
                    return tr
            return None
        if t == "ArrayExpression":
            for e in node.get("elements", []):
                if e:
                    tr = self._eval_expr(e, file_path)
                    if tr:
                        return tr
            return None
        if t == "LogicalExpression":
            return (self._eval_expr(node.get("left"), file_path)
                    or self._eval_expr(node.get("right"), file_path))
        return None

    def _handle_assign(self, node, file_path):
        right = self._eval_expr(node.get("right"), file_path)
        left = node.get("left", {})
        lt = left.get("type")

        if lt == "Identifier":
            name = left.get("name")
            if right:
                self.aliases.set_taint(name, right + [f"赋值给 {name}"])
            else:
                self.aliases.clear_taint(name)
            return right

        if lt == "MemberExpression":
            full = self._member_name(left)
            sink = self._find_member_sink(full)
            if sink and right:
                self._report(node, full, right, sink, file_path)
            obj = self._member_name(left.get("object"))
            prop = self._member_name(left.get("property"))
            if obj and prop and right:
                self.aliases.record_prop(obj, prop, right)
            return right
        return right

    def _eval_call(self, node, file_path):
        callee = node.get("callee", {})
        callee_name = self._member_name(callee) or callee.get("name", "")
        args = node.get("arguments", [])

        sink = self._find_sink(callee_name)
        if sink:
            for idx in sink.get("dangerous_arg", [0]):
                if idx < len(args):
                    tr = self._eval_expr(args[idx], file_path)
                    if tr:
                        self._report(node, callee_name, tr, sink, file_path)

        if self._is_sanitizer(callee_name):
            for a in args:
                self._eval_expr(a, file_path)
            return None

        if self._is_source_call(callee_name):
            return [f"调用 {callee_name}()（返回用户数据）"]

        cross = self._try_cross_file(callee, callee_name, args, file_path)
        if cross is not None:
            return cross or None

        for a in args:
            tr = self._eval_expr(a, file_path)
            if tr:
                return tr + [f"经 {callee_name}() 传递"]
        return None

    def _try_cross_file(self, callee, callee_name, args, file_path):
        if not self.registry or self._call_depth >= self.MAX_CROSS_FILE_DEPTH:
            return None
        imports = self.registry.get_imports(file_path)
        if not imports:
            return None

        target_info = None
        if callee.get("type") == "Identifier":
            target_info = imports.get(callee_name)
        elif callee.get("type") == "MemberExpression":
            obj_name = self._member_name(callee.get("object"))
            prop = self._member_name(callee.get("property"))
            if obj_name and (obj_name, "*") in imports.values():
                ti = imports.get(obj_name)
                if ti:
                    target_info = (ti[0], prop)

        if not target_info:
            return None
        target_file, export_name = target_info
        fn_node = self.registry.get_function(target_file, export_name)
        if not fn_node:
            return None

        tainted_args = [(i, tr) for i, a in enumerate(args)
                        if (tr := self._eval_expr(a, file_path))]
        if not tainted_args:
            return None

        self._call_depth += 1
        try:
            self._enter_cross_file_fn(fn_node, tainted_args, target_file)
        finally:
            self._call_depth -= 1
        return []

    def _enter_cross_file_fn(self, fn_node, tainted_args, target_file):
        snap_a = self.aliases.snapshot()
        snap_c = dict(self.constants)
        saved_file, saved_ret = self.current_file, self._returned

        self.aliases = AliasTracker()
        self.constants = {}
        self.current_file = target_file
        self._returned = False

        params = fn_node.get("params", [])
        for idx, tr in tainted_args:
            if idx < len(params):
                pname = params[idx].get("name")
                if pname:
                    self.aliases.set_taint(
                        pname, tr + [f"跨文件传入 {target_file}::{pname}"])

        body = fn_node.get("body", {})
        if body.get("type") == "BlockStatement":
            for s in body.get("body", []):
                if self._returned:
                    break
                self._exec_stmt(s, target_file)

        self.aliases.restore(snap_a)
        self.constants = snap_c
        self.current_file = saved_file
        self._returned = saved_ret

    def _member_name(self, node) -> str:
        if not node:
            return ""
        t = node.get("type")
        if t == "Identifier":
            return node.get("name", "")
        if t == "Literal":
            return str(node.get("value", ""))
        if t == "ThisExpression":
            return "this"
        if t == "MemberExpression":
            obj = self._member_name(node.get("object"))
            prop = self._member_name(node.get("property"))
            return f"{obj}.{prop}" if obj else str(prop)
        return ""

    def _is_source_param(self, fn):
        return any(s.get("taint_params") and s.get("name") == fn for s in self.sources)

    def _is_source_call(self, name):
        return any(s.get("taint_returns") and s.get("name") == name for s in self.sources)

    def _is_source_member(self, full):
        for s in self.sources:
            m = s.get("member")
            if m and (m == full or full.endswith("." + m)):
                return True
        return False

    def _find_sink(self, name):
        for s in self.sinks:
            if s.get("name") == name:
                return s
        for s in self.sinks:
            if name.endswith("." + s.get("name", "")):
                return s
        return None

    def _find_member_sink(self, full):
        for s in self.member_sinks:
            m = s.get("member")
            if m and full.endswith("." + m):
                return s
        return None

    def _is_sanitizer(self, name):
        for s in self.sanitizers:
            n = s.get("name", "")
            if n == name or name.endswith("." + n):
                return True
        return False

    def _report(self, node, sink_name, trace, sink, file_path):
        line = node.get("loc", {}).get("start", {}).get("line", 0)
        for f in self.findings:
            if f["file"] == file_path and f["line"] == line and sink_name in f["rule_id"]:
                return
        self.findings.append({
            "rule_id": f"TAINT-{sink_name}",
            "rule_name": f"污点传播: 用户输入 → {sink_name}",
            "severity": sink.get("severity", "medium"),
            "file": file_path, "line": line,
            "code": f"{sink_name}(...) ← 接收污点参数",
            "description": sink.get("message", "用户可控数据流入危险操作"),
            "suggestion": sink.get("suggestion", "对输入做严格校验或转义"),
            "engine": "taint",
            "trace": list(trace),
        })

    def is_tainted_expr(self, node) -> bool:
        return bool(self._eval_expr(node, self.current_file))