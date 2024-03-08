from constructs import Construct
from aws_cdk import (
    aws_sqs as sqs,
    aws_lambda as _lambda,
    aws_lambda_event_sources as event_sources,
    aws_iam as IAM
)


class SQSLambda(Construct):
    @property
    def queue(self):
        return self._queue

    def __init__(self, scope : Construct, id : str, queueName : str, tableName : str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
       
        self._queue = sqs.Queue(
            self, 'mySQS',
            queue_name = queueName,
            encryption = sqs.QueueEncryption.KMS_MANAGED,
        )

        


        

        

