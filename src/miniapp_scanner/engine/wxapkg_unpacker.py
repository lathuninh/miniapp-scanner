"""KillWxapkg 封装器。"""
import shutil
import subprocess
from pathlib import Path
from typing import Optional


class WxapkgUnpacker:
    CANDIDATES = ["KillWxapkg", "KillWxapkg.exe", "killwxapkg", "killwxapkg.exe"]

    def __init__(self, binary_path: Optional[str] = None):
        self.binary = binary_path or self._find_binary()

    def _find_binary(self) -> Optional[str]:
        for name in self.CANDIDATES:
            p = shutil.which(name)
            if p:
                return p
        for name in self.CANDIDATES:
            if Path(name).exists():
                return str(Path(name).resolve())
        return None

    def unpack(self, wxapkg_path: str, output_dir: Optional[str] = None) -> Optional[str]:
        if not self.binary:
            raise RuntimeError(
                "未找到 KillWxapkg 可执行文件。请从 "
                "https://github.com/Ackites/KillWxapkg/releases 下载并放入 PATH。"
            )
        src = Path(wxapkg_path)
        if not src.exists():
            raise FileNotFoundError(f"wxapkg 文件不存在: {src}")
        out = Path(output_dir) if output_dir else src.parent / src.stem
        out.mkdir(parents=True, exist_ok=True)
        cmd = [self.binary, f"-in={src}", f"-out={out}", "-restore", "-pretty"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            return None
        return str(out)