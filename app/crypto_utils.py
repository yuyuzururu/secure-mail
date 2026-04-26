import os
import base64
import json
from datetime import datetime
from typing import Optional, Tuple
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import constant_time

# ---------------------
# 基本工具
# ---------------------

def generate_symmetric_key(length: int = 32) -> bytes:
    """返回随机对称密钥（默认 32 字节/256 位的AES密钥）
    用于加密：
    1，邮件正文
    2，邮件证书（Certificate）
    """
    return os.urandom(length)


def compute_sha256(data: bytes) -> bytes:
    """计算SHA-256摘要：用于签名前摘要，防止内容篡改"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


# ---------------------
# RSA 密钥对与序列化
# ---------------------

def generate_rsa_keypair(key_size: int = 2048):
    """
    生成 RSA 密钥对（私钥对象 + PEM 字符串）。
    返回 (private_key_obj, private_pem_bytes, public_pem_bytes)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, private_pem, public_pem


def load_private_key_from_pem(pem_bytes: bytes, password: Optional[bytes] = None):
    """数据库中的私钥在用户输入正确密码后，还原成内存中的私钥对象"""
    return serialization.load_pem_private_key(pem_bytes, password=password)


def load_public_key_from_pem(pem_bytes: bytes):
    """从 PEM bytes 加载公钥对象"""
    return serialization.load_pem_public_key(pem_bytes)


def serialize_public_pem(public_pem_bytes: bytes) -> str:
    #将公钥 PEM 转为字符串（便于存数据库）
    return public_pem_bytes.decode("utf-8")


# ---------------------
# 私钥用密码加密/解密（用于服务器存储私钥的场景）
# 返回/接受的数据结构为 dict，内部使用 base64 编码）
# ---------------------

def _derive_key(password: str, salt: bytes, length: int = 32, iterations: int = 200_000) -> bytes:
    #使用KDF（密钥派生函数）加密用户的私钥->256位密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key_with_password(password: str, private_pem_bytes: bytes) -> dict:
    """
    用到了上面的加密函数
    使用用户密码对私钥 PEM 加密，
    并将加密所需的所有参数（salt、nonce、密文）打包成一个字典，以便存入数据库。
    返回 dict {salt, nonce, ciphertext}（均 base64 字符串）。
    """
    salt = os.urandom(16)               #确保即使两个用户用相同口令，加密结果也完全不同。————防止彩虹表攻击和批量破解。
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)                #使用派生出的密钥创建 AES-GCM 加密对象；
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, private_pem_bytes, None)
    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ct).decode("utf-8"),
    }


def decrypt_private_key_with_password(password: str, enc_dict: dict) -> bytes:
    """
    enc_dict 包含 base64 的 salt/nonce/ciphertext，返回私钥 PEM bytes，若解密失败抛异常。
    """
    salt = base64.b64decode(enc_dict["salt"])
    nonce = base64.b64decode(enc_dict["nonce"])
    ct = base64.b64decode(enc_dict["ciphertext"])
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    pem = aesgcm.decrypt(nonce, ct, None)
    return pem


# ---------------------
# AES-GCM 对称加密（正文 / 证书）
# ---------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    AES-GCM 加密，返回 (ciphertext, nonce)，ciphertext 包含 tag（AESGCM.encrypt 的输出）。
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ct, nonce


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data)
    return pt


# ---------------------
# RSA-OAEP 封装（用于加密对称密钥）
# ---------------------

def rsa_oaep_encrypt(public_key_or_pem, plaintext: bytes) -> bytes:
    """
    public_key_or_pem: 公钥对象或 PEM bytes/str
    返回 ciphertext bytes
    """
    if isinstance(public_key_or_pem, (bytes, str)):
        if isinstance(public_key_or_pem, str):
            public_key_or_pem = public_key_or_pem.encode("utf-8")
        public_key = load_public_key_from_pem(public_key_or_pem)
    else:
        public_key = public_key_or_pem

    ct = public_key.encrypt(
        plaintext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ct


def rsa_oaep_decrypt(private_key_obj, ciphertext: bytes) -> bytes:
    """
    private_key_obj: 私钥对象（cryptography）
    """
    pt = private_key_obj.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return pt


# ---------------------
# RSA-PSS 签名与验证（用于不可否认性）
# ---------------------

def rsa_pss_sign(private_key_obj, message: bytes) -> bytes:
    """
    用私钥对 message（通常为摘要）做 RSA-PSS 签名，返回 signature bytes
    """
    sig = private_key_obj.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return sig


def rsa_pss_verify(public_key_or_pem, message: bytes, signature: bytes) -> bool:
    """
    验证签名，返回 True/False
    """
    if isinstance(public_key_or_pem, (bytes, str)):
        if isinstance(public_key_or_pem, str):
            public_key_or_pem = public_key_or_pem.encode("utf-8")
        public_key = load_public_key_from_pem(public_key_or_pem)
    else:
        public_key = public_key_or_pem

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ---------------------
# 辅助：base64 编/解
# ---------------------

def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))