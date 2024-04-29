import json
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests
from env import env

templates = Jinja2Templates(directory="templates")

app = FastAPI()
# 静的ファイル
app.mount("/static", StaticFiles(directory=f"static/", html=True), name="front")

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "client_id": env.cognito_client_id,
        }
    )

@app.get("/code", response_class=HTMLResponse)
def oidc_mode_code(request: Request):
    """認可レスポンスのリダイレクションエンドポイント"""
    return templates.TemplateResponse(
        request=request,
        name="code.html",
        context={}
    )

class OidcModeTokenRequest(BaseModel):
    code: str
    nonce: str

@app.post("/api/token")
def oidc_mode_token(
    data: OidcModeTokenRequest,
):
    """認可コードをアクセストークンに交換する"""
    # トークンエンドポイント
    # https://docs.aws.amazon.com/ja_jp/cognito/latest/developerguide/token-endpoint.html
    url = "https://wng8bngabmwb.auth.ap-northeast-1.amazoncognito.com/oauth2/token"
    res = requests.post(
        url=url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
        params={
            "code": data.code,
            "client_id": env.cognito_client_id,
            "client_secret": env.cognito_client_secret,
            "redirect_uri": "http://localhost:8000/code",
            "grant_type": "authorization_code",
        }
    )
    if res.status_code != 200:
        raise HTTPException(status_code=400, detail=res.text)

    res_json = res.json()
    id_token = res_json["id_token"]
    
    cognito_url = f"https://cognito-idp.{env.aws_region}.amazonaws.com/{env.cognito_user_pool_id}"
    cognito_jwk_url = f"{cognito_url}/.well-known/jwks.json"
    print(f"COGNITO JWK URL: {cognito_jwk_url}")

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
    idinfo = jwt.decode(
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
    if not "id" in idinfo["token_use"]:
        raise Exception("Not ID Token")

    if data.nonce != idinfo["nonce"]:
        raise Exception("Nonce not match")

    return {
        "token_response": res_json,
        "idinfo": idinfo,
    }