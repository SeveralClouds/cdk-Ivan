from constructs import Construct
from aws_cdk import (
    aws_lambda as _lambda,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    RemovalPolicy,
)

class LambdaBucket(Construct):
    @property
    def handler(self):
        return self._handler

    @property
    def bucket(self):
        return self._bucket


    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self._bucket = s3.Bucket(
            self, 'myBucket',
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            event_bridge_enabled = True,
        
        )

        s3deploy.BucketDeployment(
            self, 'DeployBooksFile',
            sources=[s3deploy.Source.asset('./util')],
            destination_bucket = self._bucket,
            retain_on_delete=False,
        )

        self._handler = _lambda.Function(self, 'myLambda',
        runtime = _lambda.Runtime.PYTHON_3_9,
        handler = 'lambda-bucket.handler',
        code = _lambda.Code.from_asset('lambda'),
        environment={
            'BUCKET_NAME' : self._bucket.bucket_name
        })

        self._bucket.grant_read(self.handler)