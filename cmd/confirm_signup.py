import boto3
from env import env

username = input("USERNAME: ")
confirmation_code = input("CONFIRMATION CODE: ")

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/confirm_sign_up.html
response = cognito_idp_client.confirm_sign_up(
    ClientId=env.cognito_client_id,
    SecretHash=env.get_secret_hash(username),
    Username=username,
    ConfirmationCode=confirmation_code,
)

print(response)