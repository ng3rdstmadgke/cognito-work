# - Amazon CognitoのIDトークンのJWTをPyJWTを使って検証する | YOMON8.NET
#   https://yomon.hatenablog.com/entry/2020/07/pyjwt_validate
import requests
import json
import jwt
from jwt.algorithms import RSAAlgorithm
from env import env

id_token = input("ID TOKEN: ")
print()

cognito_url = f"https://cognito-idp.{env.aws_region}.amazonaws.com/{env.cognito_user_pool_id}"
cognito_jwk_url = f"{cognito_url}/.well-known/jwks.json"
print(f"COGNITO JWK URL: {cognito_jwk_url}")

# ID TokenのヘッダーかKey IDと署名アルゴリズムを取得
jwt_header = jwt.get_unverified_header(id_token)
key_id = jwt_header["kid"]
jwt_algorithm = jwt_header["alg"]
print(f"UNVERIFIED HEADER: {jwt_header}")


# ヘッダから取得したKey IDを使い、署名検証用の公開鍵をCognitoから取得
# 鍵は複数存在するので、ヘッダから取得したKey IDと合致するものを取得
res_cognito = requests.get(cognito_jwk_url)
jwk = None
for key in json.loads(res_cognito.text)["keys"]:
    if key["kid"] == key_id:
        jwk = key
        break
if not jwk:
    raise Exception("JWK not found")
print(f"JWK: {jwk}")

# 返却される型は AllowedRSAKeys で、これは RSAPrivateKey | RSAPublicKey のエイリアス
public_key = RSAAlgorithm.from_jwk(jwk)
print(f"PUBLIC KEY: {public_key}")

# PyJWTでid_tokenの検証とdecode
# jwt.decode: https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode
# options の verify_signature が Trueの場合、デフォルトで以下のオプションが有効になる
# - verify_exp=True トークンの有効期限を検証する (デフォルト値)
# - verify_nbf=True トークンが有効になる日時を検証する (デフォルト値)
# - verify_iat=True トークンの発行時刻を検証する (デフォルト値)
# - verify_aud=True トークンが発行された対象者(クライアントID) を検証する (デフォルト値)
# - verify_iss=True トークンの発行者 を検証する (デフォルト値)
json_payload = jwt.decode(
    id_token,
    public_key,  # 公開鍵
    algorithms=[jwt_algorithm],  # 署名アルゴリズム
    options={
        "verify_signature": True,  # 署名を検証する (デフォルト値)
        "require": ["exp", "iat", "aud", "iss"],  # 必須のクレーム。このクレームがない場合は例外を発生させる
    },
    audience=env.cognito_client_id,
    issuer=cognito_url,
)

# token_use クレームを検証（今回はIDトークンであることを確認）
if not "id" in json_payload["token_use"]:
    raise Exception("Not ID Token")

print(json.dumps(json_payload, indent=2))