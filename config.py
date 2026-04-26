import os

basedir = os.path.abspath(os.path.dirname(__file__))

class DefaultConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or \
        "sqlite:///" + os.path.join(basedir, "data.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mail settings (optional; if not set, confirmation link will be printed to server console)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "")
    MAIL_PORT = int(os.environ.get("MAIL_PORT") or 0)
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "no-reply@example.com")
    # Token expiration (seconds) for confirmation links
    MAIL_CONFIRM_TOKEN_EXPIRATION = int(os.environ.get("MAIL_CONFIRM_TOKEN_EXPIRATION", 60*60*24))  # default 24h
    # 在 DefaultConfig 中新增：
    # 私钥缓存（折中方案）配置
    KEY_CACHE_ENABLED = True  # 是否启用进程内私钥缓存（演示可开，生产视情况而定）
    KEY_CACHE_TTL_SECONDS = 600  # 私钥缓存有效期（秒）。默认 600 = 10 分钟