from app import create_app, db
from sqlalchemy import text

app = create_app()
with app.app_context():
    engine = db.engine
    print("Using DB:", app.config.get("SQLALCHEMY_DATABASE_URI"))
    # 检查 receipts 表列
    with engine.connect() as conn:
        cols = conn.execute(text("PRAGMA table_info('receipts')")).fetchall()
        print("Before cols:")
        for c in cols:
            print(" ", c)
        names = [c[1] for c in cols]
        if "created_at" in names:
            print("列 created_at 已存在，跳过添加。")
        else:
            print("加列 created_at ...")
            conn.execute(text("ALTER TABLE receipts ADD COLUMN created_at DATETIME DEFAULT (CURRENT_TIMESTAMP)"))
            cols2 = conn.execute(text("PRAGMA table_info('receipts')")).fetchall()
            print("After cols:")
            for c in cols2:
                print(" ", c)
            print("已添加 created_at（默认 CURRENT_TIMESTAMP）。")