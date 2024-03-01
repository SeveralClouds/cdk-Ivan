from aws_cdk import (
    # Duration,
    Stack,
    Aws,
    aws_apigateway as apigw,
    aws_lambda as _lambda,
    aws_iam as IAM,
    aws_ec2 as ec2,
    aws_lambda_event_sources as event_sources,
    aws_elasticache as elasticache,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3 as s3,
    aws_s3_deployment as s3_deployment,
    aws_wafv2 as wafv2,
    aws_cognito as cognito,
    aws_rds as rds,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct
from .lambdaBucket import LambdaBucket
from .lambdaDynamoDB import LambdaDynamoDB
from .SQSlambda import SQSLambda
import json as JSON

class CdkProjectStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Lambda hello world
        hello_lambda = _lambda.Function(
            self, 'HelloHandler',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('lambda'),
            handler = 'hello.handler',
        )

        # Lambda -> S3 integration
        lambdaBucket = LambdaBucket(
            self, 'LambdaBucketConstruct', 
            bucket_name='cdkprojectstack-lambdabucketconstructmybucketc0199-qomhqfdp814e',
        )

        # Lambda -> DynamoDB integration
        lambdaDynamoDB = LambdaDynamoDB(
            self, 'LambdaDynamoDBConstruct',
        )

        # SQS -> Lambda -> Comprehend & DynamoDB integration
        sqsLambda = SQSLambda(
            self, 'SQSLambdaConstruct', 
            queueName='myIntegrationSQS',
            tableName=lambdaDynamoDB.table.table_name,
        )

        # Grant permission to DynamoDB table
        lambdaDynamoDB.table.grant_read_write_data(sqsLambda.handler)


        # Custom integration
        integrationRole =   IAM.Role(
            self, 'integration-role',
            assumed_by = IAM.ServicePrincipal('apigateway.amazonaws.com'),
            managed_policies=[IAM.ManagedPolicy.from_aws_managed_policy_name('AmazonSQSFullAccess')]
        )

        integrationResponse = apigw.IntegrationResponse(
            status_code='200',
            response_templates={"application/json": ""}
        )

        integrationOptions = apigw.IntegrationOptions(
            credentials_role=integrationRole,
            integration_responses=[integrationResponse],
            request_templates={"application/json": "Action=SendMessage&MessageBody=$input.body"},
            passthrough_behavior=apigw.PassthroughBehavior.NEVER,
            request_parameters={"integration.request.header.Content-Type": "'application/x-www-form-urlencoded'"}
        )

        apiResourceSQSIntegration = apigw.AwsIntegration(
            service='sqs',
            integration_http_method='POST',
            path="{}/{}".format(Aws.ACCOUNT_ID, sqsLambda.queue.queue_name),
            options=integrationOptions
        )

        methodResponse = apigw.MethodResponse(status_code='200')


        # Cognito integration
        userPool = cognito.UserPool(
            self, 'MyUserPool',
            self_sign_up_enabled=True,
        )

        auth = apigw.CognitoUserPoolsAuthorizer(
            self, 'cognitoAuth',
            cognito_user_pools=[userPool]
        )




        # API Gateway
        api = apigw.RestApi (
            self, 'Endpoint',
        )

        book = api.root.add_resource('book')

        books = book.add_resource('books')
        books.add_method('GET', apigw.LambdaIntegration(lambdaBucket._handler),
                        authorizer = auth,
                        authorization_type = apigw.AuthorizationType.COGNITO)

        orders = book.add_resource('orders')
        orders.add_method('POST', apigw.LambdaIntegration(lambdaDynamoDB._handler),
                         authorizer = auth,
                         authorization_type = apigw.AuthorizationType.COGNITO)

        proc = book.add_resource('proc')
        proc.add_method(
            'POST', apiResourceSQSIntegration,
            method_responses=[methodResponse]
        )


        # NAT
        NAT = ec2.NatProvider.gateway()
        
        
        # VPC
        vpc = ec2.Vpc(
            self, "VPC",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                )
            ],
            nat_gateway_provider=NAT,
            nat_gateway_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            nat_gateways=1
        )




        # Select subnets from VPC
        VPCSubnetPUBLIC = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PUBLIC)
        VPCSubnetPRIVATE = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PRIVATE_ISOLATED)
        privateSubNets = [ps.subnet_id for ps in vpc.private_subnets]
        privateSubnets = vpc.select_subnets(
            subnet_type = ec2.SubnetType.PRIVATE_ISOLATED
        )
        

        # Deploy NAT Gateway
        # NAT = ec2.CfnNatGateway(
        #     self, 'MyNAT',
        #     subnet_id = vpc.private_subnets, #'subnet-0859c385b4096c7cc', # private_subnet_ids = [ps.subnet_id for ps in vpc.private_subnets]
        #     allocation_id = 'eipalloc-08540aa050ba93c9a' #'eipalloc-08540aa050ba93c9a' us  #'eipalloc-090b33762620087a1' eu
        # )

        # # Add route table entry for the NAT Gateway
        # route_table_entry = ec2.CfnRoute(
        #     self, 'MyRoute',
        #     route_table_id = 'rtb-0e8f618f4c2a122f1',
        #     destination_cidr_block = '0.0.0.0/0',
        #     nat_gateway_id = NAT.ref
        # )


        # Add route for NAT in private subnet
        route_table_entry = ec2.CfnRoute(
            self, 'MyRoute',
            route_table_id = privateSubnets.subnets[0].route_table.route_table_id,
            destination_cidr_block = '0.0.0.0/0',
            nat_gateway_id = NAT.configured_gateways[0].gateway_id
        )

        # Create SG for Lambda function
        VPCLambdaSG = ec2.SecurityGroup(
            self, 'VPCLambdaSG',
            vpc = vpc,
            description = "Allow all traffic to and out of lambda",
            allow_all_outbound = True,
        )

        #VPCLambdaSG.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.all_traffic())


        # Redis
        redisSubnetGroup = elasticache.CfnSubnetGroup(
            self, 'RedisSubnetGroup',
            subnet_ids = [privateSubnets.subnets[0].subnet_id], # privateSubNets = [ps.subnet_id for ps in vpc.private_subnets]
            description = "subnet group for redis"
        )

        redisSG = ec2.SecurityGroup(
            self, 'redis-sec-group',
            vpc = vpc,
            allow_all_outbound = True,
        )

        redisSG.add_ingress_rule(
            peer=VPCLambdaSG,
            description="Allow Lambda to access Redis",
            connection=ec2.Port.tcp(6379)
        )

        redisCluster = elasticache.CfnCacheCluster(
            self, 'redisCluster',
            engine = 'redis',
            cache_node_type = 'cache.t2.micro',
            num_cache_nodes = 1,
            cache_subnet_group_name = redisSubnetGroup.ref,
            vpc_security_group_ids = [redisSG.security_group_id],
        )

        redis_endpoint = redisCluster.attr_redis_endpoint_address

        
        # Lambda in VPC
        VPCLambda = _lambda.Function(
            self, 'vpc_lambda',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('lambda'),
            handler = 'vpc-lambda.handler',
            vpc=vpc,
            vpc_subnets=VPCSubnetPRIVATE,
            security_groups=[VPCLambdaSG],
            environment={
            'BUCKET_NAME' : lambdaBucket.bucket.bucket_name,
            'REDIS_HOST' : redis_endpoint,
            'REDIS_PORT' : '6379',
            }
        )


        # Grant permission to Lambda function to access S3 bucket
        lambdaBucket.bucket.grant_read_write(VPCLambda)

        # Set up DynamoDB Streams as event source for Lambda
        DDBEventSource = event_sources.DynamoEventSource(lambdaDynamoDB.table, starting_position=_lambda.StartingPosition.LATEST)
        VPCLambda.add_event_source(DDBEventSource)


        # Cloudfront distribution origin - S3 bucket
        cfBucket = s3.Bucket(
            self, 'cfBucket',
            access_control=s3.BucketAccessControl.PRIVATE,
        )

        OAI = cloudfront.OriginAccessIdentity(self, 'OAI')
        cfBucket.grant_read(OAI)

        s3_deployment.BucketDeployment(
            self,"myDeployment",
            destination_bucket=cfBucket,
            sources=[s3_deployment.Source.asset('./front-end')],
            retain_on_delete=False
        )
        
        # Cloudfront distribution
        # cloudfrontDistribution = cloudfront.Distribution(
        #     self, 'myDist',
        #     default_behavior=cloudfront.BehaviorOptions(
        #         origin=origins.RestApiOrigin(api),
        #         allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
        #     ),
        #     additional_behaviors={'/image/' : origins.S3Origin(cfBucket, origin_access_identity=OAI)}
        # )


        # WAF
        waf = wafv2.CfnWebACL(
            self, 'CFWAF',
            default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
            scope='CLOUDFRONT',
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled = True,
                metric_name ='WAF',
                sampled_requests_enabled = True
            ),
            rules = [
                wafv2.CfnWebACL.RuleProperty(
                    name='AWS-AWSManagedRulesCommonRuleSet',
                    priority = 1,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name='AWSManagedRulesCommonRuleSet',
                            vendor_name='AWS'
                        )
                    ),
                    visibility_config = wafv2.CfnWebACL.VisibilityConfigProperty(
                        sampled_requests_enabled=True,
                        cloud_watch_metrics_enabled=True,
                        metric_name="AWS-AWSManagedRulesCommonRuleSet",
                    ),
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(none={})
                ),
            ],
        )


        # Cloudfront distribution
        cloudfrontDistribution = cloudfront.Distribution(
            self, 'myDist',
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(cfBucket, origin_access_identity=OAI),
            ),
            additional_behaviors={'/book/*' : cloudfront.BehaviorOptions(
                origin = origins.RestApiOrigin(api),
                allowed_methods = cloudfront.AllowedMethods.ALLOW_ALL
                )
            },
            web_acl_id=waf.attr_arn,
        )


        # RDS SG
        dbSG = ec2.SecurityGroup(
            self, 'dbSG',
            vpc = vpc,
        )

        dbSG.add_ingress_rule(
            peer = VPCLambdaSG,
            description = "Allow Lambda to access RDS",
            connection = ec2.Port.tcp(5432)
        )


        # Secrets manager
        secret = secretsmanager.Secret(
            self, 'secret',
            generate_secret_string = secretsmanager.SecretStringGenerator(
                secret_string_template = JSON.dumps({'username':'postgres'}),
                generate_string_key = "password",
                exclude_characters = "\"@/\\",
                exclude_punctuation = True,
                include_space = False,
                #allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            )
        )


        # Allowing Lambda to access Secrets manager
        SecretsManagerStatement = IAM.PolicyStatement()
        SecretsManagerStatement.add_actions("secretsmanager:*")
        SecretsManagerStatement.add_resources("*")
        VPCLambda.add_to_role_policy(SecretsManagerStatement)


        # RDS
        postgre = rds.DatabaseInstance(
            self, 'postgre',
            engine = rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_15_2),
            #instace_type = ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
            vpc = vpc,
            vpc_subnets = VPCSubnetPRIVATE,
            security_groups = [dbSG],
            credentials = rds.Credentials.from_secret(secret),
            # credentials = {
            #     'username': secret.secret_value_from_json('username').to_string(),
            #     'password': secret.secret_value_from_json('password')
            # },
            database_name = 'PG_DB',
        )





        


      
        






        

        

        
