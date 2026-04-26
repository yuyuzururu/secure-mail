from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import login_required, current_user
from .models import User, Mail, Receipt
from . import db
from . import key_store
from . import mail_service
from . import crypto_utils
import json

bp = Blueprint("main", __name__, template_folder="templates")


@bp.route("/")
def index():
    if getattr(current_user, "is_authenticated", False):
        return redirect(url_for("main.inbox"))
    return redirect(url_for("auth.login"))


@bp.route("/inbox.html")
@login_required
def inbox():
    mails = Mail.query.filter_by(recipient_id=current_user.id).order_by(Mail.created_at.desc()).all()
    return render_template("inbox.html", mails=mails)


@bp.route("/sent")
@login_required
def sent():
    mails = Mail.query.filter_by(sender_id=current_user.id).order_by(Mail.created_at.desc()).all()
    return render_template("sent.html", mails=mails)


@bp.route("/compose", methods=["GET"])
@login_required
def compose():
    return render_template("compose.html")


@bp.route("/send", methods=["POST"])
@login_required
def send_mail():
    """
    支持两种流程：
    - 如果 key_store 有缓存私钥，直接使用缓存私钥发送（无密码）。
    - 否则，若 POST 中包含 op_password 字段，则使用该密码临时解密 DB 中私钥并完成发送（不缓存）。
    - 若无缓存且未提供密码，若是 AJAX 请求返回 JSON 指示需密码；否则 flash ���示并重定向到 compose。
    """
    recipient_email = request.form.get("recipient_email", "").strip().lower()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    op_password = request.form.get("op_password", None)

    if not recipient_email or not subject or not body:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "请填写收件人邮箱、主题与正文"}), 400
        flash("请填写收件人邮箱、主题与正文", "warning")
        return redirect(url_for("main.compose"))

    recipient = User.query.filter(User.email.ilike(recipient_email)).first()
    if not recipient:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "未找到该邮箱对应的注册用户"}), 404
        flash("未找到该邮箱对应的注册用户，请确认收件人已在系统注册并完成邮箱验证", "danger")
        return redirect(url_for("main.compose"))

    # 优先使用缓存私钥
    keys = key_store.get_keys(current_user.id)
    if keys:
        sender_priv_sign_obj = keys.get("priv_sign_obj")
        try:
            mail = mail_service.send_mail(current_user, recipient, subject, body, sender_priv_sign_obj)
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"ok": True, "redirect": url_for("main.sent")})
            flash("邮件已加密并保存到收件箱", "success")
            return redirect(url_for("main.sent"))
        except Exception as e:
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": f"发送邮件失败: {e}"}), 500
            flash(f"发送邮件失败: {e}", "danger")
            return redirect(url_for("main.compose"))

    # 没有缓存私钥：如果没有提供密码，提示前端需要密码
    if not op_password:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"need_password": True, "message": "发送操作需要输入解密密码以临时解密私钥"}), 403
        flash("当前会话未缓存私钥，请在提交时提供密码以临时解密私钥，或重新登录以缓存私钥。", "warning")
        return redirect(url_for("main.compose"))

    # 使用提供的密码从 DB 解密私钥（临时，不缓存）
    try:
        enc_sign = json.loads(current_user.priv_sign_encrypted)
        enc_enc = json.loads(current_user.priv_enc_encrypted)
        priv_sign_pem = crypto_utils.decrypt_private_key_with_password(op_password, enc_sign)
        priv_sign_obj = crypto_utils.load_private_key_from_pem(priv_sign_pem)
    except Exception as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": f"解密私钥失败: {e}"}), 403
        flash(f"解密私钥失败: {e}", "danger")
        return redirect(url_for("main.compose"))

    # 执行发送（不缓存私钥）
    try:
        mail = mail_service.send_mail(current_user, recipient, subject, body, priv_sign_obj)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": True, "redirect": url_for("main.sent")})
        flash("邮件已加密并保存到收件箱", "success")
        return redirect(url_for("main.sent"))
    except Exception as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": f"发送邮件失败: {e}"}), 500
        flash(f"发送邮件失败: {e}", "danger")
        return redirect(url_for("main.compose"))


@bp.route("/mail/<int:mail_id>", methods=["GET"])
@login_required
def view_mail(mail_id):
    mail = Mail.query.get_or_404(mail_id)
    is_recipient = (mail.recipient_id == current_user.id)
    is_sender = (mail.sender_id == current_user.id)

    plaintext = None
    cert = None
    signature_valid = False
    errors = []
    needs_password = False

    if is_recipient:
        keys = key_store.get_keys(current_user.id)
        if not keys:
            # 不强制重定向，指示页面显示密码输入表单
            needs_password = True
        else:
            priv_enc_obj = keys.get("priv_enc_obj")
            result = mail_service.decrypt_and_verify_mail(mail, priv_enc_obj, fetch_sender_pubkey_pem=True)
            plaintext = result.get("plaintext")
            cert = result.get("cert")
            signature_valid = result.get("signature_valid", False)
            errors = result.get("errors", [])
    else:
        # 发送方或旁观者：不自动解密
        pass

    receipts = Receipt.query.filter_by(mail_id=mail.id).all()

    return render_template("mail_view.html",
                           mail=mail,
                           is_recipient=is_recipient,
                           is_sender=is_sender,
                           plaintext=plaintext,
                           cert=cert,
                           signature_valid=signature_valid,
                           errors=errors,
                           receipts=receipts,
                           needs_password=needs_password)


@bp.route("/mail/<int:mail_id>/decrypt", methods=["POST"])
@login_required
def decrypt_mail_with_password(mail_id):
    """
    AJAX endpoint: 使用请求中的 op_password 解密单封邮件并返回 JSON（临时解密，不缓存）。
    """
    mail = Mail.query.get_or_404(mail_id)
    if mail.recipient_id != current_user.id:
        return jsonify({"error": "无权限"}), 403

    op_password = request.form.get("op_password", "")
    if not op_password:
        return jsonify({"error": "缺少密码"}), 400

    try:
        enc_sign = json.loads(current_user.priv_sign_encrypted)
        enc_enc = json.loads(current_user.priv_enc_encrypted)
        priv_enc_pem = crypto_utils.decrypt_private_key_with_password(op_password, enc_enc)
        priv_enc_obj = crypto_utils.load_private_key_from_pem(priv_enc_pem)
    except Exception as e:
        return jsonify({"error": f"解密私钥失败: {e}"}), 403

    try:
        result = mail_service.decrypt_and_verify_mail(mail, priv_enc_obj, fetch_sender_pubkey_pem=True)
        # 返回需要的字段（正文、证书、签名状态、errors）
        return jsonify({
            "ok": True,
            "plaintext": result.get("plaintext"),
            "cert": result.get("cert"),
            "signature_valid": result.get("signature_valid", False),
            "errors": result.get("errors", []),
        })
    except Exception as e:
        return jsonify({"error": f"解密/验证失败: {e}"}), 500


@bp.route("/mail/<int:mail_id>/ack", methods=["POST"])
@login_required
def ack_mail(mail_id):
    mail = Mail.query.get_or_404(mail_id)
    if mail.recipient_id != current_user.id:
        abort(403)

    keys = key_store.get_keys(current_user.id)
    op_password = request.form.get("op_password", None)

    # 如果无缓存并且前端未提供密码，提示需要密码（AJAX）
    if not keys and not op_password:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"need_password": True, "message": "签收操作需要输入解密密码以临时解密签名���钥"}), 403
        flash("当前会话未缓存私钥，请在提交时提供密码以临时解密私钥，或重新登录以缓存私钥。", "warning")
        return redirect(url_for("main.view_mail", mail_id=mail.id))

    # 优先使用缓存
    receiver_priv_sign_obj = None
    if keys:
        receiver_priv_sign_obj = keys.get("priv_sign_obj")
    else:
        # 使用提供的密码临时解密
        try:
            enc_sign = json.loads(current_user.priv_sign_encrypted)
            priv_sign_pem = crypto_utils.decrypt_private_key_with_password(op_password, enc_sign)
            receiver_priv_sign_obj = crypto_utils.load_private_key_from_pem(priv_sign_pem)
        except Exception as e:
            if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": f"解密私钥失败: {e}"}), 403
            flash(f"解密私钥失败: {e}", "danger")
            return redirect(url_for("main.view_mail", mail_id=mail.id))

    # 创建并保存签收证明（临时私钥使用后不缓存）
    try:
        receipt = mail_service.create_and_store_receipt(mail, current_user, receiver_priv_sign_obj)
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"ok": True})
        flash("签收已生成并保存。发送方将看到收讫证明。", "success")
    except Exception as e:
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": f"签收失败: {e}"}), 500
        flash(f"签收失败: {e}", "danger")

    return redirect(url_for("main.view_mail", mail_id=mail.id))


# --------------------------
# 新增：用户搜索（用于写信时自动补全）
# --------------------------
@bp.route("/api/users/search")
@login_required
def api_users_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify([])

    like_pattern = f"%{q}%"
    results = User.query.filter(
        (User.email.ilike(like_pattern)) | (User.username.ilike(like_pattern))
    ).limit(10).all()

    out = [{"id": u.id, "username": u.username, "email": u.email} for u in results]
    return jsonify(out)