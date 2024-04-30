import json
import base64
import hashlib
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests
import boto3
from env import env

templates = Jinja2Templates(directory="templates")

app = FastAPI()

# 静的ファイル
app.mount("/static", StaticFiles(directory=f"static/", html=True), name="front")

def get_code_challenge(code_verifier: str) -> str:
    """code_challengeを生成する"""
    # NOTE: code_challengeは、code_verifierをSHA256でハッシュ化し、BASE64URLエンコードしたもの
    #       code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    #       https://tex2e.github.io/rfc-translater/html/rfc7636.html#4-2--Client-Creates-the-Code-Challenge
    # 参考: https://qiita.com/gaichi/items/de83f9edd6b43ac6f15b
    return base64 \
        .urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(
            b'='
        ).decode()

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    code_verifier = "dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXk"  # NOTE: 本来はランダム文字列
    code_challenge = get_code_challenge(code_verifier)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "client_id": env.cognito_client_id,
            "code_challenge": code_challenge,
        }
    )

@app.get("/code", response_class=HTMLResponse)
def code(request: Request):
    """認可レスポンスのリダイレクションエンドポイント"""
    return templates.TemplateResponse(
        request=request,
        name="code.html",
        context={}
    )

class TokenRequest(BaseModel):
    code: str
    nonce: str

@app.post("/api/token")
def token(
    data: TokenRequest,
):
    """認可コードをアクセストークンに交換する"""
    # トークンエンドポイント | AWS
    # https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
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
            "code_verifier": "dBjftJeZ4CVPmB92K27uhbUJU1p1rwW1gFWFOEjXk"
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
        raise HTTPException(status_code=400, detail="Not ID Token")

    if data.nonce != idinfo["nonce"]:
        raise HTTPException(status_code=400, detail="Nonce not match")

    print(f"TOKEN_RESPONSE: {res_json}")
    print(f"IDINFO: {idinfo}")

    return {
        "token_response": res_json,
        "idinfo": idinfo,
    }

class RevokeRequest(BaseModel):
    refresh_token: str

@app.post("/api/revoke")
def revoke(
    data: RevokeRequest,
):
    # トークンの取り消しエンドポイント | AWS
    # https://docs.aws.amazon.com/ja_jp/cognito/latest/developerguide/revocation-endpoint.html
    # NOTE:
    #   - revokeエンドポイントはリフレッシュトークンとそれに関連するアクセストークン・IDトークンを執行させることができます。
    #   - boto3でやる場合はこちら
    #     https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/revoke_token.html
    url = "https://wng8bngabmwb.auth.ap-northeast-1.amazoncognito.com/oauth2/revoke"
    basic_auth = f"{env.cognito_client_id}:{env.cognito_client_secret}"
    res = requests.post(
        url=url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {base64.b64encode(basic_auth.encode()).decode()}"
        },
        params={
            "token": data.refresh_token,
        }
    )
    print(res)
    if res.status_code != 200:
        raise HTTPException(status_code=400, detail=res.text)
    return {"msg": "OK"}

class SignOutRequest(BaseModel):
    access_token: str

@app.post("/api/signout")
def signout(
    data: SignOutRequest,
):
    cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)
    # グローバルサインアウト | boto3
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/global_sign_out.html
    response = cognito_idp_client.global_sign_out(
        AccessToken=data.access_token,
    )
    print(response)
    return response