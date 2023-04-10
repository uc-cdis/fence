import json
import boto3


def send_message_to_queue(message, queue=None, queue_name=None, sqs_resource=None, region_name="us-east-2"):
    if sqs_resource is None:
        sqs_resource = boto3.resource("sqs", region_name=region_name)

    if queue is None:
        queue = sqs_resource.get_queue_by_name(QueueName=queue_name)

    response = queue.send_message(MessageBody=json.dumps(message))

    return response



def send_messages_to_queue(messages, queue=None, queue_name=None, sqs_resource=None, region_name="us-east-2"):
    if sqs_resource is None:
        sqs_resource = boto3.resource("sqs", region_name=region_name)

    if queue is None:
        queue = sqs_resource.get_queue_by_name(QueueName=queue_name)

    entries = [dict(Id=str(_id), MessageBody=json.dumps(message)) for _id, message in enumerate(messages)]
    response = queue.send_messages(Entries=entries)
    
    return response