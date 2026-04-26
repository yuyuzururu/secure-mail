from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    # 默认配置类
    app.config.from_object('config.DefaultConfig')
    # 尝试加载 instance/config.py（可放敏感配置）
    try:
        app.config.from_pyfile('config.py')
    except FileNotFoundError:
        pass

    # 初始化扩展
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # 导入并注册蓝图，确保 models 被导入以便迁移生效
    with app.app_context():
        # 导入蓝图对象并注册
        from .auth import bp as auth_bp
        from .routes import bp as main_bp
        app.register_blueprint(auth_bp)
        app.register_blueprint(main_bp)

        # 确保 models 模块被加载（Flask-Migrate 需要）
        from . import models  # noqa: F401
        return app