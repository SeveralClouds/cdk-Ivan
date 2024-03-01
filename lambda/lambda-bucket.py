import json
import boto3
import os

s3 = boto3.client('s3')

def handler(event, context):
    data = s3.get_object(Bucket = os.environ['BUCKET_NAME'], Key = 'main.txt')
    contents = data['Body'].read()
    cleanContents = str(contents, 'utf-8')
    
    print(contents)

    return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': cleanContents
        }