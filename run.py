import json
from typing import List

import atheris
import atheris_libprotobuf_mutator
import pika
from google.protobuf.json_format import MessageToJson

import vyperProtoNew_pb2
from config import Config
from db import get_mongo_client

with atheris.instrument_imports():
    import sys
    import vyper
    from converters.typed_converters import TypedConverter

__version__ = "0.1.0"  # same version as images' one


class QueueManager:
    def __init__(self, host, port, queue_name):
        self.host = host
        self.port = port

        # TODO: it's supposed to be refactored to support different QM's
        self._connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=host,
            port=port
        ))
        self.channel = self._connection.channel()
        self._queue_name = queue_name

        self.channel.queue_declare(queue_name)

    def publish(self, **kwargs):
        message = json.dumps(kwargs)
        self.channel.basic_publish(exchange='', routing_key=self._queue_name, body=message)


class MultiQueueManager:
    def __init__(self, queue_managers: List[QueueManager] = None):
        self.queue_managers = queue_managers if queue_managers is not None else []

    def publish(self, **kwargs):
        for queue in self.queue_managers:
            queue.publish(**kwargs)


conf = Config()

db_client = get_mongo_client(conf.db["host"], conf.db["port"])

qm = MultiQueueManager(queue_managers=[
    QueueManager(
        q_params["host"],
        q_params["port"],
        q_params["queue_name"]
    )
    for q_params in conf.compiler_queues])


@atheris.instrument_func
def TestOneProtoInput(msg):
    data = {
        "json_msg": MessageToJson(msg),
        "generation_result": None,
        "compilation_result": None,
        "error_type": None,
        "error_message": None,
        "generator_version": __version__,
    }
    c_log = db_client["compilation_log"]
    f_log = db_client['failure_log']
    try:
        proto = TypedConverter(msg)
        proto.visit()
    except Exception as e:
        f_log.insert_one({
            "error_type": type(e).__name__,
            "error_message": str(e),
            "json_msg": MessageToJson(msg),
        })
        raise e  # Do we actually want to fail here?
    data["generation_result"] = proto.result
    try:
        c_result = vyper.compile_code(proto.result)
        data["compilation_result"] = c_result
    except Exception as e:
        data["error_type"] = type(e).__name__
        data["error_message"] = str(e)
    ins_res = c_log.insert_one(data)

    message = {
        "_id": str(ins_res.inserted_id),
        "generation_result": proto.result,
        "json_msg": MessageToJson(msg),
        "generator_version": __version__,
    }
    qm.publish(**message)


if __name__ == '__main__':
    atheris_libprotobuf_mutator.Setup(
        sys.argv, TestOneProtoInput, proto=vyperProtoNew_pb2.Contract)
    atheris.Fuzz()
