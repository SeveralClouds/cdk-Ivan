import json


def handler(event, context):
    response = event["Records"][0]["cf"]["response"]
    headers = response["headers"]
    headers["x-custom-header"] = [{"key": "x-custom-header", "value": "custom-header-value"}]

    return response