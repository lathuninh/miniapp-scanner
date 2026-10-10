📝 [详细介绍文章：从零构建微信小程序安全扫描器](https://juejin.cn/post/7694595110122045483)

# miniapp-scanner
[![CI](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/lathuninh/miniapp-scanner/actions/workflows/ci.yml)

# miniapp-scanner

微信小程序静态安全扫描器：AST + 污点分析 + DSL 规则 + LLM 研判。

## 核心能力

- **四引擎检测**：正则 / AST / DSL / 污点数据流
- **跨文件追踪**：追踪 `utils/request.js` 等封装方法的完整传播链
- **别名分析**：处理 `const a=b; const c=a; c.evil()` 间接传播
- **控制流敏感**：识别 `if (false)` 分支的不可达代码
- **YAML 规则库**：22 条规则，改规则不用改代码
- **LLM 二次研判**：AI 判断 TP/FP，过滤误报
- **LLM 自动报告**：生成可交付的中文安全报告
- **用户级配置**：`~/.miniapp-scanner.yaml`，一次配置到处用

## 安装

```bash
pip install -e ".[dev]"