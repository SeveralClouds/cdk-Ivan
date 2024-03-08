from aws_cdk import (
    Duration,
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
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_ecr as ecr,
    aws_ecr_assets as ecr_assets,
    aws_sqs as sqs,
    aws_events as events,
    aws_events_targets as targets,
    RemovalPolicy,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_kms as kms,
    aws_certificatemanager as acm,
    aws_route53 as route53,
)
from constructs import Construct
from .lambdaBucket import LambdaBucket
from .lambdaDynamoDB import LambdaDynamoDB
from .SQSlambda import SQSLambda
import json as JSON


class CdkProjectStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Lambda -> S3 integration
        lambdaBucket = LambdaBucket(
            self, 'LambdaBucketConstruct', 
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



        # Custom integration: API GW -> SQS
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



        # Cognito integration with API GW
        userPool = cognito.UserPool(
            self, 'MyUserPool',
            self_sign_up_enabled=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        auth = apigw.CognitoUserPoolsAuthorizer(
            self, 'cognitoAuth',
            cognito_user_pools=[userPool]
        )



        # API Gateway
        api = apigw.RestApi (
            self, 'Endpoint',
        )

        # /book
        book = api.root.add_resource('book')

        # /book/books
        books = book.add_resource('books')
        books.add_method('GET', apigw.LambdaIntegration(lambdaBucket._handler),
                        authorizer = auth,
                        authorization_type = apigw.AuthorizationType.COGNITO)

        # /book/orders
        orders = book.add_resource('orders')
        orders.add_method('POST', apigw.LambdaIntegration(lambdaDynamoDB._handler),
                         authorizer = auth,
                         authorization_type = apigw.AuthorizationType.COGNITO)

        # /book/proc
        proc = book.add_resource('proc')
        proc.add_method(
            'POST', apiResourceSQSIntegration,
            method_responses=[methodResponse]
        )



        # NAT
        NAT = ec2.NatProvider.gateway()
        NAT2 = ec2.NatProvider.gateway()
        
        
        # VPC
        # VPC1 : Lambda, ElastiCache, RDS (PostgreSQL)
        vpc = ec2.Vpc(
            self, "VPC",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask = 18,
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask = 18,
                )
            ],
            nat_gateway_provider=NAT,
            nat_gateway_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            nat_gateways=1,
            ip_addresses = ec2.IpAddresses.cidr("10.0.0.0/16"),
        )

        # VPC2 : ALB, Fargate
        vpc2 = ec2.Vpc(
            self, "VPC2",
            max_azs=2,
            subnet_configuration = [
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type = ec2.SubnetType.PUBLIC,
                    cidr_mask = 18,
                    
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type = ec2.SubnetType.PRIVATE_ISOLATED,
                    cidr_mask = 18,
                )
            ],
            nat_gateway_provider = NAT2,
            nat_gateway_subnets = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PUBLIC),
            nat_gateways = 1,
            ip_addresses = ec2.IpAddresses.cidr("10.1.0.0/16"),
        )


        # Select subnets from VPC

        # VPC1
        VPCSubnetPUBLIC = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PUBLIC)
        VPCSubnetPRIVATE = ec2.SubnetSelection(subnet_type = ec2.SubnetType.PRIVATE_ISOLATED)

        privateSubnets = vpc.select_subnets(
            subnet_type = ec2.SubnetType.PRIVATE_ISOLATED
        )

        # VPC2
        privateSubnets2 = vpc2.select_subnets(
            subnet_type = ec2.SubnetType.PRIVATE_ISOLATED
        )



        # Add route for NAT in private subnets

        # VPC1
        route_table_entry = ec2.CfnRoute(
            self, 'MyRoute',
            route_table_id = privateSubnets.subnets[0].route_table.route_table_id,
            destination_cidr_block = '0.0.0.0/0',
            nat_gateway_id = NAT.configured_gateways[0].gateway_id
        )

        route_table_entry2 = ec2.CfnRoute(
            self, 'MyRoute2',
            route_table_id = privateSubnets.subnets[1].route_table.route_table_id,
            destination_cidr_block = '0.0.0.0/0',
            nat_gateway_id = NAT.configured_gateways[0].gateway_id
        )

        # VPC2
        route_table_entry_vpc2_1 = ec2.CfnRoute(
            self, 'MyRouteVPC21',
            route_table_id = privateSubnets2.subnets[0].route_table.route_table_id,
            destination_cidr_block = '0.0.0.0/0',
            nat_gateway_id = NAT2.configured_gateways[0].gateway_id
        )

        route_table_entry_vpc2_2 = ec2.CfnRoute(
            self, 'MyRouteVPC22',
            route_table_id = privateSubnets2.subnets[1].route_table.route_table_id,
            destination_cidr_block = '0.0.0.0/0',
            nat_gateway_id = NAT2.configured_gateways[0].gateway_id
        )



        # Create SG for Lambda function inside the VPC
        VPCLambdaSG = ec2.SecurityGroup(
            self, 'VPCLambdaSG',
            vpc = vpc,
            description = "Allow all traffic to and out of lambda",
           allow_all_outbound = True,
        )



        # Redis
        redisSubnetGroup = elasticache.CfnSubnetGroup(
            self, 'RedisSubnetGroup',
            subnet_ids = [privateSubnets.subnets[0].subnet_id],
            description = "subnet group for redis"
        )

        redisSG = ec2.SecurityGroup(
            self, 'redis-sec-group',
            vpc = vpc,
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


        # Secrets manager for RDS (PostgreSQL) credentials
        secret = secretsmanager.Secret(
            self, 'secret',
            generate_secret_string = secretsmanager.SecretStringGenerator(
                secret_string_template = JSON.dumps({'username':'postgres'}),
                generate_string_key = "password",
                exclude_characters = "\"@/\\",
                exclude_punctuation = True,
                include_space = False,
            )
        )



        # Lambda in VPC : Gets triggered by EventBridge/DDB Streams , 
        # integrates with ElastiCache, Secrets Manager, RDS (PostreSQL)
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
            'SECRET_NAME' : secret.secret_name,
            'REGION_NAME' : 'us-east-1'
            }
        )



        # Allowing VPC Lambda to access Secrets manager
        SecretsManagerStatement = IAM.PolicyStatement()
        SecretsManagerStatement.add_actions("secretsmanager:GetResourcePolicy")
        SecretsManagerStatement.add_actions("secretsmanager:GetSecretValue")
        SecretsManagerStatement.add_actions("secretsmanager:DescribeSecret")
        SecretsManagerStatement.add_actions("secretsmanager:ListSecretVersionIds")
        SecretsManagerStatement.add_resources(secret.secret_arn)
        VPCLambda.add_to_role_policy(SecretsManagerStatement)


        # Grant permission to VPC Lambda function to access S3 bucket
        lambdaBucket.bucket.grant_read_write(VPCLambda)

        # Set up DynamoDB Streams as event source for VPC Lambda
        DDBEventSource = event_sources.DynamoEventSource(lambdaDynamoDB.table, starting_position=_lambda.StartingPosition.LATEST)
        VPCLambda.add_event_source(DDBEventSource)

        # Bucket to collect logs
        bucket_logs = s3.Bucket(
            self, 'bucket_logs_cf',
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            access_control = s3.BucketAccessControl.BUCKET_OWNER_FULL_CONTROL,
            enforce_ssl = True,
            block_public_access = s3.BlockPublicAccess.BLOCK_ALL,
        )


        # Cloudfront distribution origin - S3 bucket
        cfBucket = s3.Bucket(
            self, 'cfBucket',
            access_control=s3.BucketAccessControl.PRIVATE,
            removal_policy = RemovalPolicy.DESTROY,
            auto_delete_objects = True,
            versioned = True,
            server_access_logs_bucket = bucket_logs,
            enforce_ssl = True,
        )

        OAI = cloudfront.OriginAccessIdentity(self, 'OAI')
        cfBucket.grant_read(OAI)

        s3_deployment.BucketDeployment(
            self,"myDeployment",
            destination_bucket=cfBucket,
            sources=[s3_deployment.Source.asset('./front-end')],
            retain_on_delete=False
        )
        
        
        # WAF for Cloudfront
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


        # Lambda@Edge
        lambdaEdge = cloudfront.experimental.EdgeFunction(
            self, 'lambdaEdge',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('lambda_edge'),
            handler = 'lambda_edge.handler',
        )


        # Setting up acm certificate for Cloudfront
        hosted_zone = route53.HostedZone.from_lookup(self, 'zone', domain_name='i.sevc.link')
        cert1 = acm.Certificate.from_certificate_arn(
            self, 'cert1',
            certificate_arn = 'arn:aws:acm:us-east-1:095186745110:certificate/ff740c53-5b15-44cc-ac4c-f5bb80599c3b'
        )


        # Cloudfront distribution for S3 and API GW
        cloudfrontDistribution = cloudfront.Distribution(
            self, 'myDist',
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(cfBucket, origin_access_identity=OAI),
                edge_lambdas=[cloudfront.EdgeLambda(
                    function_version=lambdaEdge.current_version,
                    event_type=cloudfront.LambdaEdgeEventType.VIEWER_RESPONSE,
                )]
            ),
            additional_behaviors={'/book/*' : cloudfront.BehaviorOptions(
                origin = origins.RestApiOrigin(api),
                allowed_methods = cloudfront.AllowedMethods.ALLOW_ALL
                )
            },
            web_acl_id=waf.attr_arn,
            default_root_object='index.html',
            domain_names = ['www.i.sevc.link'],
            certificate = cert1,
        )


        # Create CNAME record for the Cloudfront distribution
        route53.CnameRecord(
            self, 'cname',
            record_name = 'www.i.sevc.link',
            domain_name = cloudfrontDistribution.domain_name,
            zone = hosted_zone,
        )



        # RDS SG
        dbSG = ec2.SecurityGroup(
            self, 'dbSG',
            vpc = vpc,
        )

        dbSG.add_ingress_rule(
            peer = VPCLambdaSG,
            description = "Allow Lambda to access RDS",
            connection = ec2.Port.tcp(5432),
        )


        # KMS key for encryption at rest
        key = kms.Key(
            self, 'key',
            #removal_policy = RemovalPolicy.DESTROY,
        )

        # key = kms.Key.from_key_arn(
        #     self, 'key_from_arn',
        #     key_arn = 'arn:aws:kms:us-east-1:095186745110:key/354a6515-970f-47b0-a148-bc102d0354b9',
        # )


        # RDS
        postgre = rds.DatabaseInstance(
            self, 'postgreDB',
            engine = rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_15_2),
            instance_type = ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
            vpc = vpc,
            vpc_subnets = VPCSubnetPRIVATE,
            security_groups = [dbSG],
            credentials = rds.Credentials.from_secret(secret),
            database_name = 'PG_Database',
            storage_encrypted = True,
            storage_encryption_key = key,
            multi_az = True,
        )


        # Fargate cluster to poll from SQS
        ecs_cluster = ecs.Cluster(
            self, 'ecs_sqs_cluster',
            vpc = vpc,
        )

        ecs_task_definition = ecs.FargateTaskDefinition(
            self, 'ecs_sqs_task_definition',
            cpu = 256,
            memory_limit_mib = 512,
            execution_role = IAM.Role(
                self, 'role',
                assumed_by = IAM.ServicePrincipal('ecs-tasks.amazonaws.com'),
                managed_policies = [IAM.ManagedPolicy.from_aws_managed_policy_name('service-role/AmazonECSTaskExecutionRolePolicy')],
            )
        )

        ecs_task_definition.add_container(
            'ecs_sqs_container',
            environment = {"QUEUE_NAME": sqsLambda.queue.queue_name, "TABLE_NAME": lambdaDynamoDB.table.table_name, "AWS_DEFAULT_REGION":"us-east-1"},
            image = ecs.ContainerImage.from_registry('095186745110.dkr.ecr.us-east-1.amazonaws.com/cdk-hnb659fds-container-assets-095186745110-us-east-1:latest5'),
            logging = ecs.LogDrivers.aws_logs(stream_prefix='ecs_sqs'),
            readonly_root_filesystem = True,
        )

        ecs_service = ecs.FargateService(
            self, 'ecs_service_fg',
            cluster = ecs_cluster,
            task_definition = ecs_task_definition,
            desired_count = 1,
        )


        # Give permissions to the Fargate task

        # Permissions for fargate to access SQS queue
        sqs_permissions = IAM.PolicyStatement()
        sqs_permissions.add_actions("sqs:ReceiveMessage")
        sqs_permissions.add_actions("sqs:GetQueueAttributes")
        sqs_permissions.add_actions("sqs:GetQueueUrl")
        sqs_permissions.add_actions("sqs:ListQueues")
        sqs_permissions.add_resources(sqsLambda.queue.queue_arn)
        ecs_service.task_definition.add_to_task_role_policy(sqs_permissions)

        # Permissions for fargate to access DynamoDB table
        db_permissions = IAM.PolicyStatement()
        db_permissions.add_actions("dynamodb:BatchWriteItem")
        db_permissions.add_actions("dynamodb:PutItem")
        db_permissions.add_actions("dynamodb:UpdateItem")
        db_permissions.add_actions("dynamodb:DescribeTable")
        db_permissions.add_actions("dynamodb:GetRecords")
        db_permissions.add_resources(lambdaDynamoDB.table.table_arn)
        ecs_service.task_definition.add_to_task_role_policy(db_permissions)

        # Permissions for fargate to access Comprehend
        comprehend_permissions = IAM.PolicyStatement()
        comprehend_permissions.add_actions("comprehend:BatchDetectSentiment")
        comprehend_permissions.add_actions("comprehend:DescribeSentimentDetectionJob")
        comprehend_permissions.add_actions("comprehend:DescribeTargetedSentimentDetectionJob")
        comprehend_permissions.add_actions("comprehend:DetectSentiment")
        comprehend_permissions.add_actions("comprehend:ListSentimentDetectionJobs")
        comprehend_permissions.add_actions("comprehend:ListTargetedSentimentDetectionJobs")
        comprehend_permissions.add_resources("*")
        ecs_service.task_definition.add_to_task_role_policy(comprehend_permissions)



        # ALB Fargate cluster
        alb_ecs_cluster = ecs.Cluster(
            self, 'alb_cluster',
            vpc = vpc2
        )

        alb_ecs_task_definition = ecs.FargateTaskDefinition(
            self, 'ecs_alb_task_definition',
            cpu = 256,
            memory_limit_mib = 512,
            execution_role = IAM.Role(
                self, 'alb_ecs_execution_role',
                assumed_by = IAM.ServicePrincipal('ecs-tasks.amazonaws.com'),
                managed_policies = [IAM.ManagedPolicy.from_aws_managed_policy_name('service-role/AmazonECSTaskExecutionRolePolicy')],
            )
        )

        alb_ecs_task_definition.add_container(
            'ecs_alb_container',
            image = ecs.ContainerImage.from_registry('095186745110.dkr.ecr.us-east-1.amazonaws.com/cdk-hnb659fds-container-assets-095186745110-us-east-1:webFlaskV2'),
            logging = ecs.LogDrivers.aws_logs(stream_prefix='ecs_alb'),
            port_mappings = [ecs.PortMapping(container_port = 5000)], # 5000 is the port the flask app is running on
            readonly_root_filesystem = True,
        )

        alb_ecs = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, 'alb_ecs_pattern',
            cluster = alb_ecs_cluster,
            desired_count = 1,
            task_definition = alb_ecs_task_definition,
            task_subnets = ec2.SubnetSelection(
                subnets = [privateSubnets2.subnets[0]]
            ),
        )
        alb_ecs.load_balancer.set_attribute('deletion_protection.enabled', 'True')
        alb_ecs.load_balancer.log_access_logs(bucket_logs, 'alb_acc_logs')


        # Cloudfront To ALB
        cfALB = cloudfront.Distribution(
            self, 'ALB_Dist',
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin(
                    alb_ecs.load_balancer.load_balancer_dns_name,
                    protocol_policy = cloudfront.OriginProtocolPolicy.HTTP_ONLY,
                ),
                allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                     
            ),
            web_acl_id=waf.attr_arn,
            default_root_object = alb_ecs.load_balancer.load_balancer_dns_name, #REMOVE
        )  



        # Eventbridge rule triggered from S3 and calling Lambda
        rule = events.Rule(
            self, 'Rule',
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["Object Deleted"],
                detail={"bucket" : {"name" : [lambdaBucket.bucket.bucket_name]}},
            )
        )

        rule.add_target(targets.LambdaFunction(VPCLambda))
        VPCLambda.grant_invoke(IAM.ServicePrincipal('events.amazonaws.com'))



        # Defining CW alarms on metrics
        topic = sns.Topic(
            self, 'CloudWatchAlarmTopic',
            display_name = 'CloudWatchAlarmTopic',
            master_key = key,
        )
        topic.add_subscription(subscriptions.EmailSubscription('ivanstanislavov@abv.bg'))

        # Metric for error count from Lambda invocations
        metric_num_of_errors = VPCLambda.metric_errors()
        lambda_num_of_errors_alarm = cloudwatch.Alarm(
            self, 'lambda_error_invocations_alarm',
            metric = metric_num_of_errors,
            threshold = 1,
            evaluation_periods = 1,
            comparison_operator = cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        ) 
        lambda_num_of_errors_alarm.add_alarm_action(cw_actions.SnsAction(topic))


        # Metric for size of S3 bucket
        bucket_size_alarm = cloudwatch.Alarm(
            self, 'bucket_size_alarm',
            metric = cloudwatch.Metric(
                metric_name = 'BucketSizeBytes',
                namespace = 'AWS/S3',
                dimensions_map = {'BucketName': lambdaBucket.bucket.bucket_name, 'StorageType' : "StandardStorage"},
                period = Duration.days(1),
                statistic = 'Maximum'
            ),
            evaluation_periods = 1,
            threshold = 10000000000, # 10GB
        )
        bucket_size_alarm.add_alarm_action(cw_actions.SnsAction(topic))



        # Power tools lambda
        pt_func = _lambda.Function(
            self, 'power_tools_func',
            runtime = _lambda.Runtime.PYTHON_3_9,
            code = _lambda.Code.from_asset('lambda_power_tools'),
            handler = 'lambda_power_tools.handler',
        )


