from getpass import getpass
import boto3
from env import env

access_token = input("ACCESS TOKEN: ")

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/delete_user.html
response = cognito_idp_client.delete_user(
    AccessToken=access_token,
)

print(response)
