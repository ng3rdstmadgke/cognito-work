import base64
import hmac
import hashlib

from pydantic_settings import BaseSettings
from dotenv import load_dotenv


class Environment(BaseSettings):
    cognito_user_pool_id: str
    cognito_client_id: str
    cognito_client_secret: str
    aws_region: str = "ap-northeast-1"

    def get_secret_hash(self, username: str) -> str:
        # SECRET_HASH計算
        message = bytes(username + self.cognito_client_id, "utf-8")
        key = bytes(self.cognito_client_secret, "utf-8")
        secret_hash = base64.b64encode(
            hmac.new(key, message, digestmod=hashlib.sha256).digest()
        ).decode()
        return secret_hash

# .envを読み込み
load_dotenv()
env = Environment()
