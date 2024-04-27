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

# Tokenの表示
id_token = response["AuthenticationResult"]["IdToken"]
print("---- ID TOKEN ----")
print(id_token)

id_token = response["AuthenticationResult"]["AccessToken"]
print("---- Access TOKEN ----")
print(id_token)
