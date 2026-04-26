import smtplib
from itsdangerous import URLSafeTimedSerializer
from email.message import EmailMessage
from flask import current_app
import traceback

def _get_serializer(secret_key):
    return URLSafeTimedSerializer(secret_key)

def generate_confirmation_token(email: str) -> str:
    s = _get_serializer(current_app.config['SECRET_KEY'])
    return s.dumps(email, salt='email-confirm-salt')

def confirm_token(token: str, expiration: int = None):
    s = _get_serializer(current_app.config['SECRET_KEY'])
    max_age = expiration or current_app.config.get('MAIL_CONFIRM_TOKEN_EXPIRATION', 60*60*24)
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=max_age)
    except Exception:
        return None
    return email

def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    发送邮件。如果未配置 SMTP SERVER，则在服务器控制台打印确认链接以便测试。
    返�� True/False 表示是否“发送”成功（或打印成功）。
    """
    mail_server = current_app.config.get('MAIL_SERVER')
    if not mail_server:
        # fallback: print to console (开发/测试环境)
        print("=== send_email fallback: MAIL_SERVER not configured ===")
        print("To:", to_email)
        print("Subject:", subject)
        print("Body:")
        print(body)
        print("=== end ===")
        return True

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = current_app.config.get('MAIL_DEFAULT_SENDER')
        msg["To"] = to_email
        msg.set_content(body)

        server = smtplib.SMTP(mail_server, current_app.config.get('MAIL_PORT') or 0, timeout=10)
        if current_app.config.get('MAIL_USE_TLS'):
            server.starttls()
        username = current_app.config.get('MAIL_USERNAME')
        password = current_app.config.get('MAIL_PASSWORD')
        if username:
            server.login(username, password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        # 打印日志，返回 False
        print("Failed to send email:", e)
        traceback.print_exc()
        return False