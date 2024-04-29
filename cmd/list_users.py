import boto3
from env import env
from datetime import datetime
import json

cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp/client/list_users.html
response = cognito_idp_client.list_users(
    UserPoolId=env.cognito_user_pool_id,
    Limit=50,
)

def datetime_serializer(obj):
    if isinstance(obj, datetime):
        return obj.__str__()

print(json.dumps(response, default=datetime_serializer, indent=2, ensure_ascii=False))