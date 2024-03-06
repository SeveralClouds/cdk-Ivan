from boto3 import resource

QUEUE_NAME = 'myIntegrationSQS'

def get_ddb_details():
    

def get_queue_details():
    sqs = resource('sqs')
    return sqs.get_queue_by_name(QueueName=QUEUE_NAME)

def receive():
    queue = get_queue_details()
    while True:
        for message in queue.receive_messages():
            print("MESSAGE CONSUMED: {}".format(message.body))
            print(message.delete())

if __name__ == '__main__':
    receive()