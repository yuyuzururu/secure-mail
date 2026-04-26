from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from . import db, login_manager
from .models import User
from . import crypto_utils
import json
from . import key_store
from .email_utils import generate_confirmation_token, send_email, confirm_token

bp = Blueprint("auth", __name__, template_folder="templates")

@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not email or not password:
            flash("请填写所有必填项", "warning")
            return render_template("register.html")

        if password != confirm:
            flash("两次输入的密码不一致", "warning")
            return render_template("register.html")

        # 唯一性检查
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("用户名或邮箱已存在", "warning")
            return render_template("register.html")

        # 生成两对 RSA（签名与加密）
        priv_sign_obj, priv_sign_pem, pub_sign_pem = crypto_utils.generate_rsa_keypair()
        priv_enc_obj, priv_enc_pem, pub_enc_pem = crypto_utils.generate_rsa_keypair()

        # 使用用户密码加密私钥（存储 JSON）
        enc_priv_sign = crypto_utils.encrypt_private_key_with_password(password, priv_sign_pem)
        enc_priv_enc = crypto_utils.encrypt_private_key_with_password(password, priv_enc_pem)

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            pubkey_sign=crypto_utils.serialize_public_pem(pub_sign_pem),
            pubkey_enc=crypto_utils.serialize_public_pem(pub_enc_pem),
            priv_sign_encrypted=json.dumps(enc_priv_sign),
            priv_enc_encrypted=json.dumps(enc_priv_enc),
            email_confirmed=False,
        )
        db.session.add(user)
        db.session.commit()

        # 发送确认邮件（包含确认链接）；若无法发送，会在控制台打印
        token = generate_confirmation_token(email)
        confirm_url = url_for('auth.confirm_email', token=token, _external=True)
        subject = "请确认你的 Secure Mail 邮箱"
        body = f"你好 {username}，\n\n请点击以下链接确认你的邮箱并激活账户：\n\n{confirm_url}\n\n该链接将在 {current_app.config.get('MAIL_CONFIRM_TOKEN_EXPIRATION', 60*60*24)} 秒后过期。\n\n若你没有发起此请求，请忽略此邮件。"

        ok = send_email(email, subject, body)
        if ok:
            flash("已发送确认邮件，请检查你的邮箱并点击确认链接以完成注册（如果没有邮件，请检查垃圾箱）。", "success")
        else:
            flash("尝试发送确认邮件失败，请检查服务器日志（开发环境会打印确认链接）。", "warning")

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@bp.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("确认链接无效或已过期，请重新申请验证邮件。", "danger")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("未找到该用户。", "danger")
        return redirect(url_for("auth.register"))

    if user.email_confirmed:
        flash("邮箱已验证，请直接登录。", "info")
        return redirect(url_for("auth.login"))

    user.email_confirmed = True
    db.session.add(user)
    db.session.commit()
    flash("邮箱验证成功。你现在可以登录并使用系统功能。", "success")
    return redirect(url_for("auth.login"))


@bp.route("/confirm/resend", methods=["GET", "POST"])
@login_required
def resend_confirmation():
    # 仅登录用户可请求重发确认邮件（若尚未确认）
    if current_user.email_confirmed:
        flash("你的邮箱已确认，无需重发。", "info")
        return redirect(url_for("main.inbox.html"))

    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
    subject = "请确认你的 Secure Mail 邮箱（重发）"
    body = f"你好 {current_user.username}，\n\n请点击以下链接确认你的邮箱并激活账户：\n\n{confirm_url}\n\n若你没有发起此请求，请忽略此邮件。"
    ok = send_email(current_user.email, subject, body)
    if ok:
        flash("确认邮件已重发，请检查邮箱（或垃圾箱）。", "success")
    else:
        flash("重发确认邮件失败，请联系管理员或检查服务器日志。", "danger")
    return redirect(url_for("main.inbox.html"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username_or_email", "").strip()
        password = request.form.get("password", "")

        if not username_or_email or not password:
            flash("请填写用户名/邮箱和密码", "warning")
            return render_template("login.html")

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("用户名/邮箱或密码错误", "danger")
            return render_template("login.html")

        # 如果邮箱未验证，不允许登录（可改为允许登录但功能受限）
        if not user.email_confirmed:
            flash("你的邮箱尚未验证，请先检查邮箱并点击确认链接。若未收到邮件，请尝试登录后在“我的收件箱”页面重发确认邮件或联系管理员。", "warning")
            return render_template("login.html")

        # 登录成功 —— 注意：为安全起见，这里不在 session 中保存明文私钥。
        login_user(user)
        # 解密并缓存私钥（和之前逻辑保持一致）
        try:
            enc_sign = json.loads(user.priv_sign_encrypted)
            enc_enc = json.loads(user.priv_enc_encrypted)
            priv_sign_pem = crypto_utils.decrypt_private_key_with_password(password, enc_sign)
            priv_enc_pem = crypto_utils.decrypt_private_key_with_password(password, enc_enc)
            priv_sign_obj = crypto_utils.load_private_key_from_pem(priv_sign_pem)
            priv_enc_obj = crypto_utils.load_private_key_from_pem(priv_enc_pem)
            key_store.set_keys(user.id, priv_sign_obj, priv_enc_obj)
        except Exception as e:
            logout_user()
            flash(f"私钥解密失败：{e}", "danger")
            return render_template("login.html")

        flash("登录成功", "success")
        return redirect(url_for("main.inbox"))

    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    # 清理临时缓存的私钥
    try:
        key_store.remove_keys(current_user.id)
    except Exception:
        pass
    logout_user()
    flash("已登出", "info")
    return redirect(url_for("auth.login"))


# Flask-Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))