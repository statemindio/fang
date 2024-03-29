import json

import pika
from vyper import compile_code

connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672))
channel = connection.channel()

queue_name = 'to_compile'

channel.queue_declare(queue_name)


def callback(ch, method, properties, body):
    data = json.loads(body)
    print(data["_id"])
    try:
        comp = compile_code(data["result"])
        print(comp)
    except Exception as e:
        pass


channel.basic_consume(queue_name, on_message_callback=callback, auto_ack=True)
channel.start_consuming()
