import json
import logging

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

from config import Config
from db import get_mongo_client
from input_generation import InputGenerator, InputStrategy
from json_encoders import ExtendedEncoder
from queue_managers import QueueManager, MultiQueueManager

class GeneratorBase:
    def __init__(self, proto_converter):
        self.__version__ = "0.1.3"
        self.conf = Config()
        self.converter = proto_converter

        self.init_logger()
        self.init_db()
        self.init_queue()
        self.init_input_generator()

    def TestOneProtoInput(self, msg):
        data = {
            "json_msg": MessageToJson(msg),
            "generation_result": None,
            "compilation_result": None,
            "error_type": None,
            "error_message": None,
            "generator_version": self.__version__,
        }
        proto_converter = self.generate_source(msg)
        data["generation_result"] = proto_converter.result

    def generate_source(self, msg):
        try:
            proto_converter = self.converter(msg)
            proto_converter.visit()
        except Exception as e:
            converter_error = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "json_msg": MessageToJson(msg),
            }
            self.failure_log.insert_one(converter_error)

            self.logger.critical("Converter has crashed: %s", converter_error)
            raise e  # Do we actually want to fail here?
        return proto_converter

    def init_input_generator(self):
        self.input_generator = InputGenerator()

    def init_logger(self):
        logger_level = getattr(logging, self.conf.verbosity)
        self.logger = logging.getLogger("generator")
        logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logger_level)
        self.logger.info("Starting version %s", self.__version__)

    def init_db(self):
        db_client = get_mongo_client(self.conf.db["host"], self.conf.db["port"])
        self.compilation_log = db_client["compilation_log"]
        self.failure_log = db_client['failure_log']

    def init_queue(self):
        self.qm = MultiQueueManager(queue_managers=[
            QueueManager(
                q_params["host"],
                q_params["port"],
                q_params["queue_name"],
                self.logger
            )
            for q_params in self.conf.compiler_queues])
