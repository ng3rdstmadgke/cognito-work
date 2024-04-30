# 前準備

```bash
poetry install

poetry shell

source setting.sh
```


# Cognito Identity Provider API を利用したコマンド

```bash
# サインアップ
python cmd/signup.py

# 管理者によるユーザー作成 (ユーザーがログインするときに強制的に新しいパスワードの設定が要求される)
python cmd/admin_create_user.py

# サインアップの承認
python cmd/confirm_signup.py

# サインイン
python cmd/signin.py

# IDトークンの確認
python cmd/verify_id_token.py

# アクセストークンの確認
python cmd/verify_access_token.py

# ユーザー一覧
python cmd/list_users.py

# サインアウト
python cmd/signout.py

# ユーザー削除
python cmd/delete_user.py
```
