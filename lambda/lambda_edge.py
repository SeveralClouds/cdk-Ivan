import json


def handler(event, context):
    print(event)

    return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': "testing"
        }