import json
import boto3
import os 
import redis
from botocore.exceptions import ClientError
import psycopg2

# Establish connection to S3 bucket
s3 = boto3.client('s3')

# Get RDS credentials from Secrets Manager
def get_secret():
    #secret_name="secret4DA88516-A9x7YB90sNhr"
    secret_name = os.environ['SECRET_NAME']
    #region_name="us-east-1"
    region_name = os.environ['REGION_NAME']

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e

    secret = json.loads(get_secret_value_response['SecretString'])
    credential = {}
    credential['USER_NAME'] = secret['username']
    credential['PASSWORD'] = secret['password']
    credential['HOST'] = secret['host']
    credential['PORT'] = secret['port']
    credential['DB_NAME'] = secret['dbname']

    return credential


def handler(event, context):
    # Event Bridge trigger
    if("Records" not in event):
        print("EVENTBRIDGE : ")
        print(event)
        return

    # DDB Stream Remove trigger
    if(event['Records'][0]['eventName'] == "REMOVE"):
        print("Remove item event")
        print(event)
        return
    
    # DDB Stream Insert trigger
    print("START:")
    # Establish Redis connection
    r = redis.Redis(host=os.environ['REDIS_HOST'], port=os.environ['REDIS_PORT'], decode_responses=True)
    print("Connected to Redis")
    
    
    # Get data from S3 bucket
    data = s3.get_object(Bucket = os.environ['BUCKET_NAME'], Key="main.txt")
    print("Got data from S3")
    
    contents = data['Body'].read()
    bookArr = json.loads(contents)['books']
    
    print("Book array is : " + str(bookArr))
    print(event['Records'])
    

    # Add title and id to Redis
    for item in event['Records']:
        
        book_id = item['dynamodb']['NewImage']['book_id']['S']
        print("book_id is " + book_id)
    
        for book in bookArr:
            if book['isbn'] == book_id:
                print("Title is : " + book['title'])
                r.set(book_id, str(book['title']))
                print("Added " + r.get(book_id) + " to Redis")


    print("Credentials :")
    # Get Postgres credentials
    credentials = get_secret()
    user_name = credentials['USER_NAME']
    password = credentials['PASSWORD']
    rds_host = credentials['HOST']
    rds_port = credentials['PORT']
    db_name = credentials['DB_NAME']
    print("Starting postgres connection")


    # Connect to Postgres instance
    try:
        conn = psycopg2.connect(host=rds_host, user=user_name, password=password, dbname=db_name, port=rds_port)
    except psycopg2.Error as e:
        print(e)
        raise e
    
    print("Connected to Postgres")
    
    # Query the DB
    query_create = 'CREATE TABLE IF NOT EXISTS app_user (username varchar(45) NOT NULL, password varchar(450) NOT NULL, PRIMARY KEY (username))'
    query_insert = 'INSERT INTO app_user(username, password) SELECT "admin", "admin" WHERE NOT EXISTS (SELECT * FROM app_user WHERE username="admin")'
    query = 'SELECT * FROM app_user'

    query_full = "CREATE TABLE IF NOT EXISTS app_user (username varchar(45) NOT NULL, password varchar(450) NOT NULL, PRIMARY KEY (username)); INSERT INTO app_user(username, password) VALUES ('admin', 'admin') on conflict (username) do nothing; SELECT * FROM app_user"
    
    print("Starting to query the DB")
    with conn.cursor() as cur:
        # cur.execute(query_create)
        # cur.execute(query_insert)
        cur.execute(query_full)
        # Print query results
        print(cur.fetchall())

    conn.close()

    

    
    