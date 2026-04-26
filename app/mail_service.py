import json
from datetime import datetime
from typing import Dict, Any

from . import db
from .models import Mail, Receipt, User
from . import crypto_utils
from cryptography.hazmat.primitives import hashes, constant_time
import base64

# ---------------------
# 发送端：创建并保存加密邮件
# ---------------------
def send_mail(sender: User, recipient: User, subject: str, plaintext_body: str, sender_priv_sign_obj) -> Mail:
    """
    创建并保存一封加密邮件。
    参数:
      - sender: User 模型（发送方）
      - recipient: User 模型（接收方）
      - subject: 邮件主题
      - plaintext_body: 明文正文（str）
      - sender_priv_sign_obj: 发送方的私钥对象（用于签名），由调用者负责解密私钥并传入

    返回已经保存的 Mail 模型实例。
    """
    # 1. 生成一次性对称密钥 K_body, K_cert
    K_body = crypto_utils.generate_symmetric_key(32)
    K_cert = crypto_utils.generate_symmetric_key(32)

    body_bytes = plaintext_body.encode("utf-8")

    # 2. 用 AES-GCM 加密正文
    enc_body, body_nonce = crypto_utils.aes_gcm_encrypt(K_body, body_bytes, None)

    # 3. 计算正文摘要并签名（签名用于不可否认性）
    digest = crypto_utils.compute_sha256(body_bytes)
    signature = crypto_utils.rsa_pss_sign(sender_priv_sign_obj, digest)

    # 4. 构造 certificate（包含摘要、签名、时间戳、sender/recipient metadata 等）
    cert_obj = {
        "message_digest_b64": base64.b64encode(digest).decode("utf-8"),
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sender_id": sender.id,
        "sender_username": sender.username,
        "recipient_id": recipient.id,
        "recipient_username": recipient.username,
    }
    cert_bytes = json.dumps(cert_obj, ensure_ascii=False).encode("utf-8")

    # 5. 用 AES-GCM 加密 certificate（使用 K_cert）
    enc_cert, cert_nonce = crypto_utils.aes_gcm_encrypt(K_cert, cert_bytes, None)

    # 6. 用收件人公钥 RSA-OAEP 加密 K_body 与 K_cert
    enc_k_body = crypto_utils.rsa_oaep_encrypt(recipient.pubkey_enc.encode("utf-8"), K_body)
    enc_k_cert = crypto_utils.rsa_oaep_encrypt(recipient.pubkey_enc.encode("utf-8"), K_cert)

    # 7. 构建 Mail 对象并保存
    mail = Mail(
        subject=subject,
        sender_id=sender.id,
        recipient_id=recipient.id,
        enc_body=enc_body,
        body_nonce=body_nonce,
        enc_k_body=enc_k_body,
        enc_cert=enc_cert,
        cert_nonce=cert_nonce,
        enc_k_cert=enc_k_cert,
        delivered=False,
    )
    db.session.add(mail)
    db.session.commit()
    return mail


# ---------------------
# 收件端：解密并验证邮件
# ---------------------
def decrypt_and_verify_mail(mail: Mail, recipient_priv_enc_obj, fetch_sender_pubkey_pem: bool = True) -> Dict[str, Any]:
    """
    解密 mail 并验证签名。
    参数:
      - mail: Mail 模型实例
      - recipient_priv_enc_obj: 接收方用于解密封装对称密钥的私钥对象（cryptography 私钥对象）
      - fetch_sender_pubkey_pem: 是否从数据库加载发送方公钥进行验证（默认 True）

    返回 dict:
      {
        "plaintext": str,
        "cert": dict,
        "signature_valid": bool,
        "errors": [...],
      }
    """
    errors = []
    result = {"plaintext": None, "cert": None, "signature_valid": False, "errors": errors}

    try:
        # 1. 解密一次性对称密钥 K_body, K_cert
        K_body = crypto_utils.rsa_oaep_decrypt(recipient_priv_enc_obj, mail.enc_k_body)
        K_cert = crypto_utils.rsa_oaep_decrypt(recipient_priv_enc_obj, mail.enc_k_cert)
    except Exception as e:
        errors.append(f"无法解密封装的对称密钥: {e}")
        return result

    try:
        # 2. 使用 K_body 解密正文
        plaintext_bytes = crypto_utils.aes_gcm_decrypt(K_body, mail.body_nonce, mail.enc_body, None)
        result["plaintext"] = plaintext_bytes.decode("utf-8")
    except Exception as e:
        errors.append(f"正文解密失败: {e}")
        return result

    try:
        # 3. 使用 K_cert 解密证书
        cert_bytes = crypto_utils.aes_gcm_decrypt(K_cert, mail.cert_nonce, mail.enc_cert, None)
        cert_obj = json.loads(cert_bytes.decode("utf-8"))
        result["cert"] = cert_obj
    except Exception as e:
        errors.append(f"证书解密或解析失败: {e}")
        return result

    # 4. 验证签名（使用发送方公钥）
    try:
        # 获取发送方公钥 PEM（从 DB）
        if fetch_sender_pubkey_pem:
            sender = User.query.get(mail.sender_id)
            if not sender:
                errors.append("无法找到发送方用户")
                return result
            sender_pubkey_pem = sender.pubkey_sign.encode("utf-8")
        else:
            # 如果调用方提供了外部公钥，应改造为参数输入
            raise ValueError("fetch_sender_pubkey_pem=False 未实现其他路径")

        signature = base64.b64decode(cert_obj["signature_b64"])
        message_digest = base64.b64decode(cert_obj["message_digest_b64"])

        # 验证签名（rsa_pss_verify）
        valid = crypto_utils.rsa_pss_verify(sender_pubkey_pem, message_digest, signature)
        result["signature_valid"] = bool(valid)

        # 额外检查：摘要是否匹配正文
        actual_digest = crypto_utils.compute_sha256(plaintext_bytes)
        if not constant_time.bytes_eq(actual_digest, message_digest):
            errors.append("证书中记录的摘要与正文摘要不匹配（可能被篡改）")
            result["signature_valid"] = False

    except Exception as e:
        errors.append(f"签名验证失败: {e}")
        result["signature_valid"] = False

    return result


# ---------------------
# 收件端：生成签收证明并保存 Receipt
# ---------------------
def create_and_store_receipt(mail: Mail, receiver: User, receiver_priv_sign_obj) -> Receipt:
    """
    收件人在成功解密并验证邮件后生成签收证明（signed receipt）并保存到 Receipt 表。
    签收内容：message_digest || '|' || timestamp || '|' || sender_id || '|' || mail_id
    返回 Receipt 模型对象。
    """
    # 1. 从 mail 中提取原始 cert（注意：接收方需先解密证书并确保验签，路由层应执行 decrypt_and_verify_mail）
    # 这里假定调用者已经解密并验证邮件，或者直接再次解密 enc_cert（需要接收方私钥）
    # 为简化，这里我们只签名邮件 id 与当前时间与原证书摘要并保存签名
    # 尝试读取 cert: 需要先从 receiver 解密 enc_k_cert -> K_cert -> 解密 enc_cert
    # 但这里只用简化的签收格式：使用邮件 id + 当前时间 + sender_id + recipient_id + message_digest (如果可得)
    # 调用者若需要，可以先调用 decrypt_and_verify_mail 得到 cert 中的 message_digest_b64

    # 读取 cert 中的摘要（若可用）
    message_digest_b64 = None
    try:
        # attempt: decrypt enc_k_cert using receiver's encryption private key is required upstream.
        # But here we assume caller provides receiver_priv_sign_obj but not enc decryption key.
        # So if cert is not accessible here, we will only sign mail.id and timestamp.
        # To keep receipt useful, prefer the caller to pass message_digest_b64 if available.
        pass
    except Exception:
        pass

    # Build receipt payload
    timestamp = datetime.utcnow().isoformat() + "Z"
    payload_parts = [
        f"mail_id={mail.id}",
        f"sender_id={mail.sender_id}",
        f"receiver_id={receiver.id}",
        f"timestamp={timestamp}"
    ]
    payload = "|".join(payload_parts).encode("utf-8")

    # Sign payload with receiver's private signing key
    signature = crypto_utils.rsa_pss_sign(receiver_priv_sign_obj, payload)

    # Save Receipt
    receipt = Receipt(
        mail_id=mail.id,
        receiver_id=receiver.id,
        signed_receipt=signature,
    )
    db.session.add(receipt)
    db.session.commit()
    return receipt