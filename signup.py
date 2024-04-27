from getpass import getpass
import boto3
from env import env

username = input("USERNAME: ")
password = getpass("PASSWORD: ")

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/sign_up.html
response = cognito_idp_client.sign_up(
    ClientId=env.cognito_client_id,
    SecretHash=env.get_secret_hash(username),
    Username=username,
    Password=password,
)

print(response)
