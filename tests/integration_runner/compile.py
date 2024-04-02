import json

import pika
from vyper import compile_code
from db import get_mongo_client

db_ = get_mongo_client()
compilation_results = db_["compilation_results"]

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672))
channel = connection.channel()

queue_name = 'to_compile'

channel.queue_declare(queue_name)


def callback(ch, method, properties, body):
    data = json.loads(body)
    print(data["_id"])
    gen = {
        "generation_id": data["_id"]
    }
    try:
        comp = compile_code(data["result"])
        print(comp)
        gen.update(comp)
    except Exception as e:
        gen.update({"error": str(e)})
    compilation_results.insert_one(gen)


channel.basic_consume(queue_name, on_message_callback=callback, auto_ack=True)
channel.start_consuming()
