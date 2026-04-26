from app import create_app, db
from sqlalchemy import text

def show_and_add_column():
    app = create_app()
    with app.app_context():
        uri = app.config.get("SQLALCHEMY_DATABASE_URI")
        print("SQLALCHEMY_DATABASE_URI =", uri)

        engine = db.engine  # 使用推荐的 engine 属性
        # 列出所有表
        try:
            with engine.connect() as conn:
                tables = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()
            print("Tables:", [t[0] for t in tables])
        except Exception as e:
            print("列出表时出错:", e)
            return

        # 如果 users 表不存在，直接提示
        tbls = [t[0] for t in tables]
        if "users" not in tbls:
            print("未检测到 users 表。请先运行 setup_db.py 创建表，或检查 DATABASE_URL。")
            return

        # 列出 users 表列信息
        try:
            with engine.connect() as conn:
                cols = conn.execute(text("PRAGMA table_info('users')")).fetchall()
            print("users table columns (cid, name, type, notnull, dflt_value, pk):")
            for c in cols:
                print(" ", c)
            col_names = [c[1] for c in cols]
        except Exception as e:
            print("查询 users 列信息出错:", e)
            return

        if "email_confirmed" in col_names:
            print("users.email_confirmed 已存在， 无需修改。")
            return

        # 尝试添加列（SQLite 支持简单的 ALTER TABLE ADD COLUMN）
        try:
            sql = "ALTER TABLE users ADD COLUMN email_confirmed INTEGER DEFAULT 0"
            print("执行:", sql)
            with engine.connect() as conn:
                conn.execute(text(sql))
            # 再次显示列信息
            with engine.connect() as conn:
                cols2 = conn.execute(text("PRAGMA table_info('users')")).fetchall()
            print("添加后 users 列信息：")
            for c in cols2:
                print(" ", c)
            print("已成功添加 users.email_confirmed（默认 0）。")
        except Exception as e:
            print("添加列时出错:", e)

if __name__ == "__main__":
    show_and_add_column()