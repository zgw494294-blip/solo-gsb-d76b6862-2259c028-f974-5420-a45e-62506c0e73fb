"""本地撤销名单:按包摘要撤销单个已签名召回规则包,不连带同一 kid 的其他包。

名单为本地 JSON(路径由环境变量 RECALL_REVOCATION_FILE 指定;未设置时不启用
撤销检查,保持旧行为),顶层仅含 "revoked" 数组,元素为 64 位小写十六进制
SHA-256 摘要,允许重复:

{
  "revoked": [
    "9f2c...(64 位小写十六进制)"
  ]
}

包标识 = JWS 原始前两段以点连接后的 ASCII 字节(header.payload)的 SHA-256,
与签名段编码无关;同一 kid 签发的其他包不受影响。

名单在每次签名核验时重新读取:宿主机原子替换文件后下一次请求即生效,无需重启。
已配置但文件不可读、结构或元素非法时抛 RevocationStoreError(服务端配置问题,
500),绝不沿用旧名单放行。
"""

from __future__ import annotations

import hashlib
import json
import os

# 未设置(或为空)表示不启用撤销检查
DEFAULT_REVOCATION_FILE = os.environ.get("RECALL_REVOCATION_FILE") or None

_HEX_LOWER = set("0123456789abcdef")


class RevocationStoreError(RuntimeError):
    """撤销名单已配置但文件不可读或内容非法(服务端配置问题)。"""


def package_digest(header_seg: str, payload_seg: str) -> str:
    """包标识:JWS 原始前两段以点连接后的 ASCII 字节的 SHA-256(小写十六进制)。

    与签名输入为同一串字节,但不包含签名段;签名段编码变化不影响标识。
    """
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    return hashlib.sha256(signing_input).hexdigest()


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in _HEX_LOWER for ch in value)
    )


def _load_revocation_file(path: str) -> frozenset[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        raise RevocationStoreError(f"撤销名单文件不存在: {path}") from exc
    except OSError as exc:
        raise RevocationStoreError(f"撤销名单文件无法读取: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RevocationStoreError(f"撤销名单文件不是合法 JSON: {path}: {exc}") from exc

    if not isinstance(data, dict) or set(data.keys()) != {"revoked"}:
        raise RevocationStoreError(
            "撤销名单结构非法: 顶层须为仅含 'revoked' 数组的对象"
        )
    entries = data["revoked"]
    if not isinstance(entries, list):
        raise RevocationStoreError("撤销名单结构非法: 'revoked' 须为数组")

    revoked: set[str] = set()
    for index, entry in enumerate(entries):
        if not _is_digest(entry):
            raise RevocationStoreError(
                f"撤销名单 revoked[{index}] 非法: 须为 64 位小写十六进制 SHA-256 摘要"
            )
        revoked.add(entry)  # 允许重复,去重存储
    return frozenset(revoked)


def load_revoked_digests(path: str) -> frozenset[str]:
    """读取撤销名单,返回已撤销包摘要集合;每次调用都重新读文件。"""
    return _load_revocation_file(path)
