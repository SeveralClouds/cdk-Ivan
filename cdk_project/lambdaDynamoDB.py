from constructs import Construct
from aws_cdk import (
    aws_dynamodb as ddb,
    aws_lambda as _lambda,
    RemovalPolicy,
)

class LambdaDynamoDB(Construct):
    @property
    def handler(self):
        return self._handler

    @property
    def table(self):
        return self._table


    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self._table = ddb.Table(
            self, 'Orders',
            partition_key = {'name': 'order_id', 'type': ddb.AttributeType.STRING},
            stream = ddb.StreamViewType.NEW_IMAGE,
            table_name = 'orders',
            removal_policy = RemovalPolicy.DESTROY,
        )

        self._handler = _lambda.Function(
            self, 'myLambdaDDB',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('lambda'),
            handler = 'lambda-dynamodb.handler',
            environment = {
                'TABLE_NAME': self._table.table_name,
            }
        )

        self._table.grant_read_write_data(self._handler)