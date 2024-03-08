from aws_lambda_powertools import Logger

logger = Logger()

@logger.inject_lambda_context
def handler(event, context):
    logger.info(f"Received event: {event}")
    return {"message": "Hello World"}