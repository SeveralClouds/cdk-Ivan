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

    # @property
    # def handler(self):
    #     return self._handler

    def __init__(self, scope : Construct, id : str, queueName : str, tableName : str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
       
        self._queue = sqs.Queue(
            self, 'mySQS',
            queue_name = queueName,
        )

        # self._handler = _lambda.Function(
        #     self, 'mySQSLambda',
        #     runtime = _lambda.Runtime.PYTHON_3_9,
        #     code = _lambda.Code.from_asset('lambda'),
        #     handler = 'sqs-lambda.handler',
        #     environment={
        #         "TABLE_NAME" : tableName,
        #     }
        # )

        # sqsEventSource = event_sources.SqsEventSource(self._queue)
        # self._handler.add_event_source(sqsEventSource)

        # statement = IAM.PolicyStatement()
        # statement.add_actions("comprehend:*")
        # statement.add_resources("*")

        # self._handler.add_to_role_policy(statement)

        


        

        

