from getpass import getpass
import boto3
from env import env
from warrant.aws_srp import AWSSRP

username = input("USERNAME: ")
password = getpass("PASSWORD: ")
cognito_idp_client = boto3.client("cognito-idp", region_name=env.aws_region)

# warrant | Github: https://github.com/capless/warrant?tab=readme-ov-file#using-awssrp
# NOTE: Python3.8 までしか対応していない
aws_srp = AWSSRP(
    username=username,
    password=password,
    pool_id=env.cognito_user_pool_id,
    client_id=env.cognito_client_id,
    client=cognito_idp_client
)

tokens = aws_srp.authenticate_user()

from pprint import pprint
pprint(tokens)