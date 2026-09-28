import argparse
import json
from pathlib import Path

from .scanner import Scanner, ReportGenerator


def main(argv=None):
    parser = argparse.ArgumentParser(description="小程序安全漏洞扫描器 v5")
    parser.add_argument("target", nargs="?", help="目录 / 单文件 / .wxapkg")
    parser.add_argument("--rules", help="规则目录（默认：包内置）")
    parser.add_argument("--out", help=".wxapkg 解包输出目录")
    parser.add_argument("--json", metavar="FILE", help="导出 JSON 报告")
    parser.add_argument("--llm", action="store_true", help="启用 LLM 研判与报告")
    parser.add_argument("--llm-report", metavar="FILE", help="LLM Markdown 报告路径")
    parser.add_argument("--llm-profile", metavar="NAME",
                        help="用户配置里的 profile 名（~/.miniapp-scanner.yaml）")
    parser.add_argument("--init-config", action="store_true",
                        help="生成用户配置示例文件到 ~/.miniapp-scanner.yaml")
    args = parser.parse_args(argv)
    if args.init_config:
        from .config import write_example_config
        path = write_example_config()
        print(f"✅ 已生成配置示例：{path}")
        print(f"   打开文件，把 api_key 改成你的真实密钥即可。")
        return

    if not args.target:
        parser.error("the following arguments are required: target")
    if args.init_config:
        from .config import write_example_config, get_config_path
        path = write_example_config()
        print(f"✅ 已生成配置示例：{path}")
        print(f"   打开文件，把 api_key 改成你的真实密钥即可。")
        return

    scanner = Scanner(rules_dir=args.rules)
    report = scanner.scan(args.target, output_dir=args.out)

    triage_map = {}
    llm_client = None
    use_llm = args.llm or args.llm_report
    if use_llm:
        from .llm.client import LLMClient
        from .llm.triage import LLMTriager
        llm_client = LLMClient(profile=args.llm_profile)
        if not llm_client.available():
            print("⚠️  LLM 未配置（缺少 LLM_API_KEY），跳过。\n")
            use_llm = False
        else:
            print(f"[LLM] {llm_client.model} @ {llm_client.base_url}")
            triager = LLMTriager(llm_client)
            for i, f in enumerate(report["findings"], 1):
                key = f"{f['rule_id']}|{f['file']}|{f['line']}"
                triage_map[key] = triager.triage(f)
                print(f"  [{i}/{len(report['findings'])}] "
                      f"{f['rule_id']} → {triage_map[key]['verdict']}")

    print()
    print(ReportGenerator.to_console(report, triage_map or None))

    if args.json:
        Path(args.json).write_text(
            json.dumps({**report, "triage": triage_map},
                       ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"\n📁 JSON 报告: {args.json}")

    if use_llm and args.llm_report:
        from .llm.reporter import LLMReporter
        print("\n[LLM] 生成 Markdown 报告...")
        md = LLMReporter(llm_client).generate(report, triage_map)
        Path(args.llm_report).write_text(md, encoding="utf-8")
        print(f"📝 LLM 报告: {args.llm_report}")


if __name__ == "__main__":
    main()