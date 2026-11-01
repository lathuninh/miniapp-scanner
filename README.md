[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-MiniApp%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/miniapp-security-scan)
[![CI](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/miniapp-scanner)](https://pypi.org/project/miniapp-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
📝 [第一篇：从零构建微信小程序安全扫描器](https://juejin.cn/post/7694595110122045483)
📝 [第二篇：深入浅出：如何用 Python 实现一个小程序污点分析引擎](https://juejin.cn/spost/7695613699441213494)
📝 [第三篇：从 0 到 GitHub Marketplace：一个安全工具的开源全记录](https://juejin.cn/post/7697162867456114703)
📝 [第四篇：从微信小程序到全端：一个安全扫描器的演进之路](https://juejin.cn/post/7697569354293051427)
📝 [第五篇：用 AI 驱动安全审计：我是如何用自己写的工具扫 4 万行真实商业代码的](https://juejin.cn/post/7700511283238780991)
📝 [第六篇：纯 Python 性能优化的极限探讨：从 138 秒到 122 秒，再到 3 秒的狂想](https://juejin.cn/post/7702759616728350755)
# miniapp-scanner
[![CI](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml)

# miniapp-scanner

微信小程序静态安全扫描器：AST + 污点分析 + DSL 规则 + LLM 研判。

## 核心能力

- 四引擎检测：正则 / AST / DSL / 污点数据流
- 跨文件追踪：追踪 `utils/request.js` 等封装方法的完整传播链
- **跨文件返回值传播**：追踪 `getUserInput()` 返回值的污染传播
- 别名分析：处理 `const a=b; const c=a; c.evil()` 间接传播
- 控制流敏感：识别 `if (false)` 分支的不可达代码
- YAML 规则库：**25+ 条规则**，改规则不用改代码
- **Web 应用支持**：XSS（`innerHTML` / `document.write`）、DOM Clobbering
- LLM 二次研判：AI 判断 TP/FP，过滤误报
- LLM 自动报告：生成可交付的中文安全报告
- 用户级配置：`~/.miniapp-scanner.yaml`，一次配置到处用
- **PR 自动扫描**：GitHub Actions 在 PR 里自动评论扫描结果
- **25 个单元测试**：覆盖四引擎 + 所有规则
- ## 支持的框架

- ✅ **微信原生小程序**
- ✅ **Taro**（React 语法）
- ✅ **uni-app**（Vue 语法）
- ✅ **Web 应用**（React / Vue / 原生 JS）
- ✅ **React 组件**（`export default` 支持）
- ✅ **Vue 单文件组件**（`<script>` 支持）

## 安装

```bash
pip install -e ".[dev]"

## 🔧 集成到你的项目（GitHub Actions）

在你的项目里创建 `.github/workflows/security.yml`：

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: MiniApp Security Scan
        uses: lathuninh/miniapp-scanner@main
        with:
          target: '.'
          fail-on-high: 'true'

security-scan:
  stage: test
  image: python:3.11
  script:
    - pip install miniapp-scanner
    - miniapp-scanner "src/" --json report.json
    - python -c "import json; d=json.load(open('report.json')); exit(1 if d['summary']['high'] > 0 else 0)"
  artifacts:
    paths:
      - report.json

stage('Security Scan') {
    steps {
        sh 'pip install miniapp-scanner'
        sh 'miniapp-scanner "src/" --json report.json'
        script {
            def report = readJSON file: 'report.json'
            if (report.summary.high > 0) {
                error("Found ${report.summary.high} high severity issues")
            }
        }
    }
}

pip install miniapp-scanner
miniapp-scanner "src/" --json report.json

# 有高危时退出码为 1，无高危时退出码为 0
# 可通过 $? 检查，让 CI 自动阻断合并

{
  "target": "src/",
  "project_type": "miniapp",
  "files_scanned": 52,
  "lines_scanned": 5774,
  "duration": 9.6,
  "summary": {
    "total": 9,
    "high": 2,
    "medium": 0,
    "low": 6,
    "info": 1
  },
  "findings": [
    {
      "rule_id": "DSL-003",
      "rule_name": "Sensitive data stored in local storage",
      "severity": "high",
      "file": "pages/authorize/index.js",
      "line": 115,
      "code": "wx.setStorageSync('token', ...)",
      "engine": "dsl",
      "trace": []
    }
  ]
}