from getpass import getpass
import boto3
from env import env

username = input("USERNAME: ")

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)

# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/admin_create_user.html
response = cognito_idp_client.admin_create_user(
    UserPoolId=env.cognito_user_pool_id,
    Username=username,
    TemporaryPassword="H0geh0ge+",
    DesiredDeliveryMediums=[ 'EMAIL' ],  # ウェルカムメッセージの送信先
)


print(response)
