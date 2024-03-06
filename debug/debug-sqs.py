import boto3
import os
import json
#os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
QUEUE_NAME = os.environ['QUEUE_NAME']
TABLE_NAME = os.environ['TABLE_NAME']

def get_ddb_details():
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(TABLE_NAME)
    return table
#'CdkProjectStack-LambdaDynamoDBConstructOrders2AADB327-37IWCT7JDR8V'
def get_comprehend_details():
    comprehend = boto3.client('comprehend')
    return comprehend

def get_queue_details():
    sqs = boto3.resource('sqs')
    return sqs.get_queue_by_name(QueueName=QUEUE_NAME)

def receive(table, comprehend):
    queue = get_queue_details()
    while True:
        for message in queue.receive_messages():
            print("MESSAGE CONSUMED: {}".format(message.body))
            
            sentiment = comprehend.detect_sentiment(Text=json.loads(message.body)['review'], LanguageCode='en')['Sentiment']
            table.put_item(Item={'order_id': json.loads(message.body)['order_id'], 'sentiment': sentiment, 'book_id': json.loads(message.body)['book_id'] })
            message.delete()


if __name__ == '__main__':
    print("Container has started the python program")
    table = get_ddb_details()
    comprehend = get_comprehend_details()

    receive(table, comprehend)
    

    # sqs = boto3.client('sqs', region_name='us-east-1')
    # q = sqs.get_queue_by_name(QueueName=QUEUE_NAME)

    # print(q.url)