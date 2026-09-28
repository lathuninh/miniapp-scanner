#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置加载器
优先级：命令行参数 > 环境变量 > 项目 .env > 用户配置 > 默认值
"""
import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:
    yaml = None


# 默认配置
DEFAULTS = {
    "llm": {
        "api_key": "",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
    }
}


def _user_config_path() -> Path:
    """用户级配置文件路径：~/.miniapp-scanner.yaml"""
    return Path.home() / ".miniapp-scanner.yaml"


def _find_project_env(start: Optional[Path] = None) -> Optional[Path]:
    """从当前目录向上查找项目根目录的 .env 文件"""
    here = (start or Path.cwd()).resolve()
    for parent in [here] + list(here.parents):
        env_file = parent / ".env"
        if env_file.exists():
            return env_file
        # 到 git 根目录就停
        if (parent / ".git").exists():
            return None
    return None


def _load_env_file(path: Path) -> Dict[str, str]:
    """解析 .env 文件"""
    result = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k:
            result[k] = v
    return result


def _load_user_config() -> Dict[str, Any]:
    """加载 ~/.miniapp-scanner.yaml"""
    path = _user_config_path()
    if not path.exists() or yaml is None:
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def get_llm_config(profile: Optional[str] = None) -> Dict[str, str]:
    """
    按优先级加载 LLM 配置。
    profile: 指定 profile 名（对应用户配置里的 profiles.xxx）
    """
    config = dict(DEFAULTS["llm"])

    # 1. 用户配置
    user_cfg = _load_user_config()
    if profile and "profiles" in user_cfg:
        profile_cfg = user_cfg.get("profiles", {}).get(profile)
        if profile_cfg:
            config.update({k: str(v) for k, v in profile_cfg.items() if v is not None})
    elif "llm" in user_cfg and isinstance(user_cfg["llm"], dict):
        config.update({k: str(v) for k, v in user_cfg["llm"].items() if v is not None})
    elif "profiles" in user_cfg:
        # 没指定 profile，用 default_profile
        dp = user_cfg.get("default_profile")
        if dp and dp in user_cfg["profiles"]:
            config.update({k: str(v) for k, v in user_cfg["profiles"][dp].items()
                           if v is not None})

    # 2. 项目 .env
    env_file = _find_project_env()
    if env_file:
        env_vars = _load_env_file(env_file)
        for k in ("api_key", "base_url", "model"):
            env_key = f"LLM_{k.upper()}"
            if env_key in env_vars:
                config[k] = env_vars[env_key]

    # 3. 环境变量（覆盖前面所有）
    for k in ("api_key", "base_url", "model"):
        env_key = f"LLM_{k.upper()}"
        if env_key in os.environ and os.environ[env_key]:
            config[k] = os.environ[env_key]

    return config


def get_config_path() -> Path:
    return _user_config_path()


def write_example_config(overwrite: bool = False) -> Path:
    """生成一份示例用户配置文件"""
    path = _user_config_path()
    if path.exists() and not overwrite:
        return path
    content = """# miniapp-scanner 用户配置文件
# 位置：~/.miniapp-scanner.yaml
#
# 加载优先级：命令行参数 > 环境变量 > 项目 .env > 本文件 > 默认值
#
# 简单写法（所有项目共用一套配置）：
llm:
  api_key: sk-your-key-here
  base_url: https://api.deepseek.com/v1
  model: deepseek-chat

# 进阶写法（多 profile 切换）：
# default_profile: deepseek
#
# profiles:
#   deepseek:
#     api_key: sk-deepseek-xxx
#     base_url: https://api.deepseek.com/v1
#     model: deepseek-chat
#
#   openai:
#     api_key: sk-openai-xxx
#     base_url: https://api.openai.com/v1
#     model: gpt-4o-mini
#
#   local:
#     api_key: ollama
#     base_url: http://localhost:11434/v1
#     model: qwen2.5:7b
"""
    path.write_text(content, encoding="utf-8")
    return path