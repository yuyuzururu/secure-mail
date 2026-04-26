"""
短时加密内存缓存（折中方案）：

API（保持兼容）：
- set_keys(user_id, priv_sign_obj, priv_enc_obj)
- get_keys(user_id) -> dict or None, dict contains 'priv_sign_obj' and 'priv_enc_obj'
- remove_keys(user_id)

实现细节：
- 使用 Flask app.config['SECRET_KEY'] 派生一个 Fernet key（SHA256 -> urlsafe_b64encode）。
- 将私钥序列化为 PEM（无密码），然后用 Fernet 加密，连同到期时间存入进程内 dict。
- 每次 set/get/remove 时会清理过期条目。
注意：此缓存为进程内实现，多进程/多容器部署时请改用集中缓存（Redis）或改为要求用户在敏感操作时输入密码。
"""
import time
import threading
import base64
import hashlib
from typing import Optional, Dict, Any

from flask import current_app
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

# 内存结构：{ user_id: {"enc_sign": b"...", "enc_enc": b"...", "expires_at": float} }
_store = {}
_lock = threading.RLock()


def _derive_fernet_key() -> bytes:
    """
    从 Flask SECRET_KEY 派生 Fernet key（32 bytes base64 urlsafe）。
    """
    sk = current_app.config.get("SECRET_KEY", "")
    if not isinstance(sk, (bytes, bytearray)):
        sk = sk.encode("utf-8")
    digest = hashlib.sha256(sk).digest()
    return base64.urlsafe_b64encode(digest)


def _get_fernet() -> Fernet:
    return Fernet(_derive_fernet_key())


def _cleanup_expired():
    """
    清理过期条目（在每次操作时调用以避免额外线程）。
    """
    now = time.time()
    with _lock:
        remove_keys = [uid for uid, v in _store.items() if v.get("expires_at", 0) <= now]
        for uid in remove_keys:
            try:
                del _store[uid]
            except KeyError:
                pass


def set_keys(user_id: int, priv_sign_obj, priv_enc_obj) -> None:
    """
    存储私钥（对象），内部会序列化为 PEM 并加密保存。
    如果 KEY_CACHE_ENABLED 配置为 False，将不会保存（只是清理并返回）。
    """
    _cleanup_expired()

    enabled = current_app.config.get("KEY_CACHE_ENABLED", True)
    if not enabled:
        return

    ttl = int(current_app.config.get("KEY_CACHE_TTL_SECONDS", 600))
    f = _get_fernet()

    # 将私钥对象序列化为 PEM（不加密）
    sign_pem = priv_sign_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    enc_pem = priv_enc_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    enc_sign = f.encrypt(sign_pem)
    enc_enc = f.encrypt(enc_pem)

    expires_at = time.time() + ttl
    with _lock:
        _store[user_id] = {"enc_sign": enc_sign, "enc_enc": enc_enc, "expires_at": expires_at}


def get_keys(user_id: int) -> Optional[Dict[str, Any]]:
    """
    获取缓存的私钥对象（解密后加载为 cryptography 私钥对象）。
    若未启用缓存或条目不存在或已过期，返回 None。
    """
    _cleanup_expired()
    enabled = current_app.config.get("KEY_CACHE_ENABLED", True)
    if not enabled:
        return None

    with _lock:
        entry = _store.get(user_id)
        if not entry:
            return None
        enc_sign = entry.get("enc_sign")
        enc_enc = entry.get("enc_enc")
        expires_at = entry.get("expires_at", 0)

    if not enc_sign or not enc_enc:
        return None

    # 如果已过期（额外检查）
    if time.time() > expires_at:
        # 清理并返回 None
        with _lock:
            _store.pop(user_id, None)
        return None

    # 解密并加载私钥对象
    f = _get_fernet()
    try:
        sign_pem = f.decrypt(enc_sign)
        enc_pem = f.decrypt(enc_enc)
        priv_sign_obj = serialization.load_pem_private_key(sign_pem, password=None)
        priv_enc_obj = serialization.load_pem_private_key(enc_pem, password=None)
        return {"priv_sign_obj": priv_sign_obj, "priv_enc_obj": priv_enc_obj}
    except Exception:
        # 出现解密/加载错误时清理条目以避免重复错误
        with _lock:
            _store.pop(user_id, None)
        return None


def remove_keys(user_id: int) -> None:
    _cleanup_expired()
    with _lock:
        _store.pop(user_id, None)


def force_clear_all() -> None:
    """仅用于调试：清空所有缓存（慎用）。"""
    with _lock:
        _store.clear()