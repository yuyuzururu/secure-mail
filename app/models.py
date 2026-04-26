from datetime import datetime
from flask_login import UserMixin
from . import db
import json

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Email verified flag
    email_confirmed = db.Column(db.Boolean, default=False, index=True)

    # Public keys (PEM, stored as text)
    pubkey_sign = db.Column(db.Text, nullable=False)  # 用于签名验证（公钥 PEM）
    pubkey_enc = db.Column(db.Text, nullable=False)   # 用于加密对称密钥（公钥 PEM）

    # Encrypted private keys (JSON string storing salt/nonce/ciphertext in base64)
    priv_sign_encrypted = db.Column(db.Text, nullable=False)
    priv_enc_encrypted = db.Column(db.Text, nullable=False)

    # Salt or metadata may also be embedded into the JSON above; kept for clarity
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sent_mails = db.relationship("Mail", back_populates="sender", foreign_keys="Mail.sender_id")
    received_mails = db.relationship("Mail", back_populates="recipient", foreign_keys="Mail.recipient_id")
    receipts = db.relationship("Receipt", back_populates="receiver")

    def to_dict_public(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "pubkey_sign": self.pubkey_sign,
            "pubkey_enc": self.pubkey_enc,
        }

    def __repr__(self):
        return f"<User {self.username}>"


class Mail(db.Model):
    __tablename__ = "mails"
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    sender = db.relationship("User", foreign_keys=[sender_id], back_populates="sent_mails")
    recipient = db.relationship("User", foreign_keys=[recipient_id], back_populates="received_mails")

    # Encrypted fields and metadata
    enc_body = db.Column(db.LargeBinary, nullable=False)       # AES-GCM 密文（正文）
    body_nonce = db.Column(db.LargeBinary, nullable=False)
    enc_k_body = db.Column(db.LargeBinary, nullable=False)    # RSA-OAEP 对 K_body 的加密

    enc_cert = db.Column(db.LargeBinary, nullable=False)      # 证书/签名元数据（AES-GCM 加密）
    cert_nonce = db.Column(db.LargeBinary, nullable=False)
    enc_k_cert = db.Column(db.LargeBinary, nullable=False)    # RSA-OAEP 对 K_cert 的加密

    delivered = db.Column(db.Boolean, default=False)

    receipts = db.relationship("Receipt", back_populates="mail")

    def __repr__(self):
        return f"<Mail {self.id} {self.subject} from {self.sender_id} to {self.recipient_id}>"


class Receipt(db.Model):
    __tablename__ = "receipts"
    id = db.Column(db.Integer, primary_key=True)
    mail_id = db.Column(db.Integer, db.ForeignKey('mails.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # signed_receipt stores the receipt bytes (e.g. signature) as binary
    signed_receipt = db.Column(db.LargeBinary, nullable=False)
    # 将模型属性 created_at 映射到数据库中已经存在的 'timestamp' 列
    created_at = db.Column('timestamp', db.DateTime, default=datetime.utcnow, nullable=False)
    #timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    mail = db.relationship("Mail", back_populates="receipts")
    receiver = db.relationship("User", back_populates="receipts")

    def __repr__(self):
        return f"<Receipt mail={self.mail_id} receiver={self.receiver_id}>"