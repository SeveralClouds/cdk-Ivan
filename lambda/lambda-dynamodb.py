import json
import os

import boto3
ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['TABLE_NAME'])

def handler(event, context):
    order_id = json.loads(event['body'])['order_id']
    book_id = json.loads(event['body'])['book_id']


    table.put_item(Item = {'order_id' : order_id, 'book_id' : book_id})

    return {
        'statusCode' : 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }

