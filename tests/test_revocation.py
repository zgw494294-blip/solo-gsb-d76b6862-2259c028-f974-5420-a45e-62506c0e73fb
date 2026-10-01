"""POST /v1/recall/check-signed 单包撤销(本地撤销名单)的端到端测试。"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app import signed
from app.main import app
from app.revocation import package_digest

client = TestClient(app, raise_server_exceptions=False)

FNC1 = "\x1d"  # ASCII 29

KID = "recall-key-test-001"
GTIN = "09506001123454"  # make_gtin("0950600112345")
NBF = 1_789_999_000
NOW = 1_790_000_000
EXP = 1_790_086_400

SCAN = "]d2" + "01" + GTIN + "17" + "251231" + "10" + "LOT1" + FNC1 + "21SN9"
RULE = {
    "id": "recall-2026-001",
    "gtin": GTIN,
    "batch": "LOT1",
    "date_from": "2025-01-01",
    "date_to": "2026-12-31",
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url(raw)


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(autouse=True)
def trust_file(tmp_path, monkeypatch, private_key):
    """信任文件指向临时文件;默认不配置撤销名单(保持旧行为)。"""
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "kid": KID,
                        "public_key": _public_b64(private_key),
                        "gtin_prefixes": ["0950600"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(signed, "DEFAULT_TRUST_FILE", str(path))
    monkeypatch.setattr(signed, "DEFAULT_REVOCATION_FILE", None)
    return path


@pytest.fixture
def revocation_file(tmp_path, monkeypatch):
    """配置一份初始为空的撤销名单文件。"""
    path = tmp_path / "revocations.json"
    path.write_text(json.dumps({"revoked": []}), encoding="utf-8")
    monkeypatch.setattr(signed, "DEFAULT_REVOCATION_FILE", str(path))
    return path


def make_jws(private_key: Ed25519PrivateKey, payload: object, **kwargs) -> str:
    header = {"alg": "EdDSA", "kid": KID}
    header_seg = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_seg = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = private_key.sign(f"{header_seg}.{payload_seg}".encode("ascii"))
    return f"{header_seg}.{payload_seg}.{_b64url(signature)}"


def valid_payload(**overrides) -> dict:
    payload = {"nbf": NBF, "exp": EXP, "rules": [RULE]}
    payload.update(overrides)
    return payload


def digest_of(jws: str) -> str:
    header_seg, payload_seg, _ = jws.split(".")
    return hashlib.sha256(f"{header_seg}.{payload_seg}".encode("ascii")).hexdigest()


def write_list(path, entries) -> None:
    path.write_text(json.dumps({"revoked": entries}), encoding="utf-8")


def post(jws: str, *, now: int = NOW):
    return client.post(
        "/v1/recall/check-signed",
        json={"scans": [SCAN], "jws": jws, "now": now},
    )


# ---------- 未配置名单:保持旧行为 ----------


def test_not_configured_keeps_old_behavior(private_key):
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 200, resp.text
    assert resp.json()["results"][0]["matches"] == ["recall-2026-001"]


# ---------- 名单命中 / 未命中 ----------


def test_revoked_package_is_403_without_results(private_key, revocation_file):
    jws = make_jws(private_key, valid_payload())
    write_list(revocation_file, [digest_of(jws)])
    resp = post(jws)
    assert resp.status_code == 403
    assert "results" not in resp.json()
    assert "撤销" in resp.json()["detail"]


def test_empty_list_passes(private_key, revocation_file):
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 200, resp.text


def test_unrelated_digest_list_passes(private_key, revocation_file):
    write_list(revocation_file, [hashlib.sha256(b"other-package").hexdigest()])
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 200, resp.text


def test_same_kid_other_package_not_revoked(private_key, revocation_file):
    """单包撤销:不连带撤销同一 kid 的其他包。"""
    revoked_jws = make_jws(private_key, valid_payload())
    write_list(revocation_file, [digest_of(revoked_jws)])

    other_rule = {**RULE, "id": "recall-2026-002", "batch": "LOT2"}
    other_jws = make_jws(private_key, valid_payload(rules=[other_rule]))
    resp = post(other_jws)
    assert resp.status_code == 200, resp.text
    assert resp.json()["kid"] == KID


def test_duplicate_entries_allowed(private_key, revocation_file):
    jws = make_jws(private_key, valid_payload())
    digest = digest_of(jws)
    write_list(revocation_file, [digest, digest, digest])
    assert post(jws).status_code == 403


def test_digest_ignores_signature_segment(private_key):
    """包标识只取原始前两段:签名段不同、标识相同。"""
    jws = make_jws(private_key, valid_payload())
    header_seg, payload_seg, signature_seg = jws.split(".")
    other = f"{header_seg}.{payload_seg}.{'A' * len(signature_seg)}"
    assert package_digest(*other.split(".")[:2]) == digest_of(jws)
    # 标识就是 header.payload 原始 ASCII 字节的 SHA-256,与解码内容无关
    assert package_digest(header_seg, payload_seg) == digest_of(jws)


# ---------- 名单已配置但非法:500,不放行 ----------


def test_missing_revocation_file_is_500(private_key, tmp_path, monkeypatch):
    monkeypatch.setattr(
        signed, "DEFAULT_REVOCATION_FILE", str(tmp_path / "missing.json")
    )
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 500
    assert "results" not in resp.json()


def test_invalid_json_is_500(private_key, revocation_file):
    revocation_file.write_text("{not json", encoding="utf-8")
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 500


@pytest.mark.parametrize(
    "content",
    [
        json.dumps([1, 2]),  # 顶层不是对象
        json.dumps({}),  # 缺 revoked
        json.dumps({"revoked": [], "extra": 1}),  # 仅允许 revoked 一个键
        json.dumps({"revoked": "abc"}),  # revoked 不是数组
    ],
)
def test_invalid_structure_is_500(private_key, revocation_file, content):
    revocation_file.write_text(content, encoding="utf-8")
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 500


@pytest.mark.parametrize(
    "entry",
    [
        123,  # 不是字符串
        "a" * 63,  # 长度不足
        "a" * 65,  # 长度超限
        "A" * 64,  # 大写十六进制非法
        "g" * 64,  # 非十六进制字符
        hashlib.sha256(b"x").hexdigest() + "=",  # 含非法字符
    ],
)
def test_invalid_entry_is_500(private_key, revocation_file, entry):
    write_list(revocation_file, [entry])
    resp = post(make_jws(private_key, valid_payload()))
    assert resp.status_code == 500


def test_no_fallback_to_old_list(private_key, revocation_file):
    """名单曾可读不代表以后可读:文件变非法后报 500,不沿用旧名单放行。"""
    jws = make_jws(private_key, valid_payload())
    write_list(revocation_file, [digest_of(jws)])
    assert post(jws).status_code == 403

    revocation_file.write_text("{broken", encoding="utf-8")
    resp = post(jws)
    assert resp.status_code == 500
    assert "results" not in resp.json()


# ---------- 原子替换即时生效 ----------


def test_atomic_replace_takes_effect_without_restart(private_key, revocation_file):
    jws = make_jws(private_key, valid_payload())
    assert post(jws).status_code == 200  # 初始空名单

    # 宿主机原子替换(先写临时文件再 rename),下一次请求即生效
    tmp = revocation_file.with_suffix(".tmp")
    tmp.write_text(json.dumps({"revoked": [digest_of(jws)]}), encoding="utf-8")
    tmp.replace(revocation_file)
    assert post(jws).status_code == 403

    # 换回空名单后恢复放行
    tmp.write_text(json.dumps({"revoked": []}), encoding="utf-8")
    tmp.replace(revocation_file)
    assert post(jws).status_code == 200


# ---------- 撤销检查在验签 / 时间窗 / 前缀授权之后 ----------


def test_bad_signature_still_reports_signature_failure(private_key, revocation_file):
    jws = make_jws(private_key, valid_payload())
    write_list(revocation_file, [digest_of(jws)])
    header_seg, payload_seg, _ = jws.split(".")
    other_key = Ed25519PrivateKey.generate()
    bad_sig = _b64url(other_key.sign(f"{header_seg}.{payload_seg}".encode("ascii")))
    resp = post(f"{header_seg}.{payload_seg}.{bad_sig}")
    assert resp.status_code == 403
    assert "签名验证失败" in resp.json()["detail"]


def test_expired_revoked_package_reports_time_window(private_key, revocation_file):
    jws = make_jws(private_key, valid_payload())
    write_list(revocation_file, [digest_of(jws)])
    resp = post(jws, now=EXP)  # now >= exp,时间窗越期
    assert resp.status_code == 403
    assert "越期" in resp.json()["detail"]
