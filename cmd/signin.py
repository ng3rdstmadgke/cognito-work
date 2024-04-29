from getpass import getpass
import boto3
from env import env

username = input("USERNAME: ")
password = getpass("PASSWORD: ")

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)

# Cognitoから認証情報取得
secret_hash = env.get_secret_hash(username)
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/initiate_auth.html
response = cognito_idp_client.initiate_auth(
    AuthFlow="USER_PASSWORD_AUTH",
    AuthParameters={
        "USERNAME": username,
        "PASSWORD": password,
        "SECRET_HASH": secret_hash,
    },
    ClientId=env.cognito_client_id,
)

# NOTE: admin_create_userで作成したユーザーは初回ログイン時にパスワード変更が必要
if "ChallengeName" in response and response["ChallengeName"] == "NEW_PASSWORD_REQUIRED":
    print("NEW_PASSWORD_REQUIRED")
    new_password = getpass("NEW PASSWORD: ")
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/respond_to_auth_challenge.html
    response = cognito_idp_client.respond_to_auth_challenge(
        ChallengeName="NEW_PASSWORD_REQUIRED",
        ClientId=env.cognito_client_id,
        ChallengeResponses={
            "USERNAME": username,
            "NEW_PASSWORD": new_password,
            "SECRET_HASH": secret_hash,
        },
        Session=response["Session"],
    )

# Tokenの表示
id_token = response["AuthenticationResult"]["IdToken"]
print("---- ID TOKEN ----")
print(id_token)

id_token = response["AuthenticationResult"]["AccessToken"]
print("---- Access TOKEN ----")
print(id_token)
