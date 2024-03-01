# import json
# import boto3
# import os 
# import subprocess
# import sys


# s3 = boto3.client('s3')
# subprocess.call('pip3 install redis -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
# sys.path.insert(1, '/tmp/')
# import redis

# def handler(event, context):
#     r = redis.Redis(host=os.environ['REDIS_HOST'], port=os.environ['REDIS_PORT'], decode_responses=True)
#     data = s3.get_object(Bucket = os.environ['BUCKET_NAME'], Key="main.txt")
#     contents = data['Body'].read()
    
#     bookArr = json.loads(contents)['books']
#     print(event['Records'])
#     for item in event['Records']:
        
#         book_id = item['dynamodb']['NewImage']['book_id']['S']
#         print("book_id is " + book_id)
    

#         for book in bookArr:
#             if book['isbn'] == book_id:
#                 print("Title is : " + book['title'])
#                 r.set(book_id, str(book['title']))
#                 print("Added " + r.get(book_id) + " to Redis")

import boto3
from botocore.exceptions import ClientError

def get_secret():
    secret_name="secret4DA88516-A9x7YB90sNhr"
    region_name="us-east-1"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e

    secret = get_secret_value_response['SecretString']

    print(secret)

def handler(event, context):
    get_secret()
    return
    
    