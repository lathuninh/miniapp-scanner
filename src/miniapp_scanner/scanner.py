"""扫描器主流程。"""
import os
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

import yaml

from .engine.ast_analyzer import AstAnalyzer
from .engine.module_graph import ModuleGraph
from .engine.obfuscation_preprocessor import ObfuscationPreprocessor
from .engine.rule_dsl import RuleDSL
from .engine.taint_analyzer import TaintAnalyzer
from .engine.wxapkg_unpacker import WxapkgUnpacker

DEFAULT_RULES_DIR = Path(__file__).parent / "rules"


class Scanner:
    SCAN_EXT = {".js", ".json", ".ts"}
    JS_EXT = {".js", ".ts"}

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self.obf = ObfuscationPreprocessor()
        self.ast_analyzer = AstAnalyzer()
        self.regex_rules: List[Dict] = []
        self.ast_rules: List[Dict] = []
        self.dsl_rules: List[RuleDSL] = []
        self.taint_analyzer: Optional[TaintAnalyzer] = None
        self._load_rules()

    def _load_rules(self):
        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            if yaml_file.name == "taint.yaml":
                continue
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            rules = data.get("rules", [])
            if yaml_file.name == "dsl_rules.yaml":
                self.dsl_rules.extend(RuleDSL.load_all(data))
                continue
            for r in rules:
                ctype = r.get("check", {}).get("type")
                if ctype == "regex":
                    self.regex_rules.append(r)
                elif ctype == "ast":
                    self.ast_rules.append(r)

        taint_file = self.rules_dir / "taint.yaml"
        taint_cfg = (yaml.safe_load(taint_file.read_text(encoding="utf-8"))
                     if taint_file.exists() else {}) or {}
        self.taint_analyzer = TaintAnalyzer(taint_cfg)

        self._compiled_regex = [
            (r, re.compile(r["check"]["pattern"]),
             re.compile(r["check"].get("file_filter", ".*")))
            for r in self.regex_rules
        ]

    def _detect_project_type(self, root: Path) -> str:
        """检测项目类型：miniapp / web / node / unknown"""
        if not root.is_dir():
            return "unknown"
        if (root / "app.json").exists() and (root / "pages").exists():
            return "miniapp"
        if (root / "pages").exists() and (
                (root / "app.wxss").exists() or (root / "app.js").exists()
        ):
            return "miniapp"
        if (root / "package.json").exists() and (
                (root / "index.html").exists()
                or (root / "app" / "index.html").exists()
        ):
            # Web 应用特征：index.html + 任意 JS 文件
            if (root / "index.html").exists() or (root / "app" / "index.html").exists():
                return "web"
        if (root / "package.json").exists():
            return "node"
        return "unknown"

    def scan(self, target: str, output_dir: Optional[str] = None) -> Dict:
        tp = Path(target)
        if tp.suffix == ".wxapkg":
            unpacker = WxapkgUnpacker()
            unpacked = unpacker.unpack(str(tp), output_dir)
            if not unpacked:
                raise RuntimeError("解包失败")
            tp = Path(unpacked)

        t0 = time.time()

        # 检测项目类型
        project_type = self._detect_project_type(tp)
        if project_type == "web":
            print("⚠️  检测到 Web 应用（非微信小程序），部分小程序规则可能不适用")
        elif project_type == "node":
            print("⚠️  检测到 Node 项目，可能不是小程序源码")
        elif project_type == "unknown":
            print("⚠️  未能识别项目类型，按通用规则扫描")

        report = {
            "target": str(tp),
            "project_type": project_type,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files_scanned": 0,
            "lines_scanned": 0,
            "findings": [],
            "duration": 0.0,
            "obfuscated_files": [],
        }

        if tp.is_dir():
            try:
                self.taint_analyzer.registry = ModuleGraph(tp)
            except Exception:
                self.taint_analyzer.registry = None
        else:
            self.taint_analyzer.registry = None

        for fp in self._collect_files(tp):
            report["files_scanned"] += 1
            report["lines_scanned"] += self._scan_file(fp, tp, report)

        report["obfuscated_files"] = self.obf.report()
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        eng = {"taint": 0, "dsl": 1, "ast": 2, "regex": 3}
        report["findings"].sort(key=lambda f: (
            order.get(f["severity"], 9),
            eng.get(f["engine"], 9),
            f["file"], f["line"],
        ))
        report["duration"] = round(time.time() - t0, 3)
        report["summary"] = self._summary(report["findings"])
        return report

    def _collect_files(self, root: Path) -> List[Path]:
        import re as _re
        if root.is_file():
            return [root] if root.suffix in self.SCAN_EXT else []
        EXCLUDE_DIRS = {"node_modules", ".git", "dist", "wxParse", "__MACOSX"}
        EXCLUDE_FILE_PATTERNS = [
            r"\.min\.js$",
            r"[/\\]runtime\.js$",
            r"\.bundle\.js$",
            r"[/\\]showdown\.js$",
            r"weapp\.qrcode.*\.js$",
        ]
        MAX_FILE_SIZE = 500 * 1024        # ★ 新增：跳过 500KB+ 的文件
        result: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.suffix not in self.SCAN_EXT:
                    continue
                try:
                    if fp.stat().st_size > MAX_FILE_SIZE:      # ★ 跳过超大文件
                        continue
                except Exception:
                    continue
                rel = str(fp.relative_to(root)) if root.is_dir() else fn
                if any(_re.search(p, rel) for p in EXCLUDE_FILE_PATTERNS):
                    continue
                result.append(fp)
        return result

    def _scan_file(self, fp: Path, root: Path, report: Dict) -> int:
        try:
            # 用内存映射或更快读取
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return 0
        text = self.obf.preprocess(text, str(fp))
        rel = str(fp.relative_to(root)) if root.is_dir() else fp.name
        lines = text.splitlines()
        existing = {(f["rule_id"], f["file"], f["line"]) for f in report["findings"]}

        for rule, pat, fpat in self._compiled_regex:
            if not fpat.match(rel):
                continue
            for m in pat.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                key = (rule["id"], rel, line_no)
                if key in existing:
                    continue
                existing.add(key)
                snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else m.group(0)
                report["findings"].append({
                    "rule_id": rule["id"],
                    "rule_name": rule["info"]["name"],
                    "severity": rule["info"]["severity"],
                    "file": rel, "line": line_no,
                    "code": snippet[:160],
                    "description": rule["info"]["description"],
                    "suggestion": rule["info"]["suggestion"],
                    "engine": "regex", "trace": [],
                })

        if fp.suffix not in self.JS_EXT:
            return len(lines)

        taint_findings = self.taint_analyzer.analyze(text, rel)
        for tf in taint_findings:
            key = (tf["rule_id"], tf["file"], tf["line"])
            if key in existing:
                continue
            existing.add(key)
            report["findings"].append(tf)

        def taint_lookup(node):
            return bool(self.taint_analyzer._eval_expr(node, rel))

        ast_findings = self.ast_analyzer.analyze(
            text, rel, self.ast_rules,
            dsl_rules=self.dsl_rules, taint_lookup=taint_lookup,
        )
        for af in ast_findings:
            key = (af["rule_id"], af["file"], af["line"])
            if key in existing:
                continue
            existing.add(key)
            af.setdefault("trace", [])
            report["findings"].append(af)

        return len(lines)

    @staticmethod
    def _summary(findings: List[Dict]) -> Dict:
        s = {"total": len(findings), "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f["severity"] in s:
                s[f["severity"]] += 1
        return s


class ReportGenerator:
    ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}

    @staticmethod
    def to_console(report: Dict, triage_map: Optional[Dict] = None) -> str:
        s = report["summary"]
        out = ["=" * 72,
               "  🛡️  小程序安全漏洞扫描报告 v5",
               "=" * 72,
               f"  目标     : {report['target']}",
               f"  扫描时间 : {report['start_time']}   耗时: {report['duration']}s",
               f"  文件数   : {report['files_scanned']}   代码行数: {report['lines_scanned']}",
               "-" * 72,
                f"  漏洞总数 : {s['total']}   🔴 {s['high']}   🟠 {s['medium']}   🟡 {s['low']}   ⚪ {s.get('info', 0)}",
               "=" * 72]
        if report.get("obfuscated_files"):
            out.append(f"  ⚠️  检测到 {len(report['obfuscated_files'])} 个混淆文件")
        if not report["findings"]:
            out.append("\n  ✅ 未发现已知漏洞。\n")
            return "\n".join(out)

        for i, f in enumerate(report["findings"], 1):
            icon = ReportGenerator.ICON.get(f["severity"], "⚪")
            out.append(f"\n{icon} [{i}] {f['rule_name']}  "
                       f"({f['rule_id']} / {f['severity']}) [{f['engine'].upper()}]")
            out.append(f"    📍 {f['file']}:{f['line']}")
            out.append(f"    📄 {f['code']}")
            out.append(f"    ⚠️  {f['description']}")
            if f.get("trace"):
                out.append("    🧬 污点路径:")
                for step in f["trace"]:
                    out.append(f"       → {step}")
            out.append(f"    💡 {f['suggestion']}")
            if triage_map:
                key = f"{f['rule_id']}|{f['file']}|{f['line']}"
                tr = triage_map.get(key)
                if tr:
                    out.append(f"    🤖 研判: {tr['verdict']} "
                               f"(置信度 {tr['confidence']}) — {tr['reason']}")
        out.append("\n" + "=" * 72)
        return "\n".join(out)

