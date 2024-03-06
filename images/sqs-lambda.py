import json
import os
import boto3
from boto3.dynamodb.conditions import Attr

ddb = boto3.resource('dynamodb')
table = ddb.Table(os.environ['TABLE_NAME'])
comprehend = boto3.client('comprehend')

def handler(event, context):
    # book_id = json.loads(event['body'])['book_id']
    for message in event['Records']:
        process_message(message)
    print("done")       

    # response = table.query(
    #     FilterExpression='book_id = :book_id',
    # )

    # print(response['Items'])

def process_message(message):
    try: 
        book_id = json.loads(message['body'])['book_id']
        response = table.scan(
            FilterExpression=Attr('book_id').eq(book_id)
        )
        print("There are : " + str(len(response['Items'])) + " items with book_id " + str(book_id))

        sentiment = comprehend.detect_sentiment(Text=json.loads(message['body'])['review'], LanguageCode='en')['Sentiment']
        print("Sentiment is : " + str(sentiment))
    except Exception as err:
        print("An error has occured")
        raise err

    