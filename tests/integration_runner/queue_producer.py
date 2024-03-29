import json
import time

import pika

from db import get_mongo_client

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672))
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

    print("\n\t[ * ] Handled {} messages".format(counter))

    time.sleep(5)
