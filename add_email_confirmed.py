# add_email_confirmed.py（放在项目根）
from app import create_app, db
from sqlalchemy import text

app = create_app()

with app.app_context():
    engine = db.get_engine()
    # SQLite: 使用 INTEGER 代表布尔，默认 0（未验证）
    sql = "ALTER TABLE users ADD COLUMN email_confirmed INTEGER DEFAULT 0"
    with engine.connect() as conn:
        try:
            conn.execute(text(sql))
            print("列 email_confirmed 已添加（默认 0）。")
        except Exception as e:
            print("添加列时发生异常：", e)


