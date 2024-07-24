import json
import os
import time
import logging

import pika

from db import get_mongo_client

# TODO: get level from config
logger = logging.getLogger("generator")
logging.basicConfig(format='%(levelname)s:%(asctime)s:%(message)s', level=logging.INFO)


connection = pika.BlockingConnection(pika.ConnectionParameters(
    host=os.environ.get('QUEUE_BROKER_HOST', 'localhost'),
    port=int(os.environ.get('QUEUE_BROKER_PORT', 5672))
))
channel = connection.channel()

queue_name = 'to_compile'

channel.queue_declare(queue_name)

db_queue = get_mongo_client()
queue = db_queue["test_col"]

counter = 0

while True:
    to_add = queue.find({"in_queue": False}, limit=1000)

    for doc in to_add:
        to_queue = json.dumps({"_id": str(doc["_id"]), "result": doc["result"]})
        channel.basic_publish(exchange='', routing_key=queue_name, body=to_queue)
        queue.update_one({"_id": doc["_id"]}, {"$set": {"in_queue": True}})
        counter += 1

    logger.info("[ * ] Handled %s messages", counter)
    #print("[ * ] Handled {} messages\n".format(counter))

    time.sleep(5)
