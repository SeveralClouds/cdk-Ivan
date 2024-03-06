FROM amazon/aws-lambda-python:latest

RUN apt update -y && apt install -y python3 python3-dev python3-pip gcc && rm -Rf /var/cache/yum

COPY sqs-lambda.py ./

CMD ["sqs-lambda.handler"]
