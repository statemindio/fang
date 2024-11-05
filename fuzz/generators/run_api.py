import sys
import json
import logging

import atheris
import atheris_libprotobuf_mutator
from google.protobuf.json_format import MessageToJson

from fuzz.helpers.config import Config
from fuzz.helpers.db import get_mongo_client
from fuzz.generators.input_generation import InputGenerator, InputStrategy
from fuzz.helpers.json_encoders import ExtendedEncoder
from fuzz.helpers.queue_managers import QueueManager, MultiQueueManager

import fuzz.helpers.proto_loader as proto


class GeneratorBase:

    # Add new converters if necessary into new variables
    def __init__(self, proto_converter, config_file=None):
        self.__version__ = "0.1.3"
        self.conf = Config(config_file) if config_file is not None else Config()
        self.converter = proto_converter

        self.init_logger()
        self.init_db()
        self.init_queue()
        self.init_input_generator()

    def start_generator(self):
        atheris_libprotobuf_mutator.Setup(
            sys.argv, self.TestOneProtoInput, proto=proto.Contract)
        atheris.Fuzz()

    def TestOneProtoInput(self, msg):
        # For diff fuzzing add generation_result_{name}
        data = {
            "json_msg": MessageToJson(msg),
            "generation_result": None,
            "compilation_result": None,
            "error_type": None,
            "error_message": None,
            "generator_version": self.__version__,
        }
        proto_converter = self.generate_source(msg, self.converter)

        # For diff fuzzing other compiler results
        data["generation_result"] = proto_converter.result

        # Must be overridden
        c_result, c_error = self.compile_source(proto_converter.result)
        if c_error is None:
            data["compilation_result"] = c_result
        else:
            data["error_type"] = type(c_error).__name__
            data["error_message"] = str(c_error)

        self.logger.debug("Compilation result: %s", data)

        input_values = self.generate_inputs(proto_converter.function_inputs)
        self.logger.debug("Generated inputs: %s", input_values)
        data["function_input_values"] = input_values

        insert = self.compilation_log.insert_one(data)

        # For diff fuzzing add the results
        message = {
            "_id": str(insert.inserted_id),
            "generation_result": proto_converter.result,
            "function_input_values": input_values,
            "json_msg": MessageToJson(msg),
            "generator_version": self.__version__,
        }
        self.qm.publish(**message)

        # Creating the result entry, so there's no race condition in runners
        self.run_results.insert_one({'generation_id': str(insert.inserted_id)})

    def generate_inputs(self, function_inputs):
        input_values = dict()
        for name, types in function_inputs.items():
            for i in self.conf.input_strategies:
                self.input_generator.change_strategy(InputStrategy(i))

                if input_values.get(name, None) is None:
                    input_values[name] = []
                input_values[name].append(self.input_generator.generate(types))

        input_values = json.dumps(input_values, cls=ExtendedEncoder)
        return input_values

    # returns (result, error)
    def compile_source(self, proto_result):
        raise Exception("Need Override")
        """
        try:
            c_result = vyper.compile_code(proto_result)
            return c_result, None
        except Exception as e:
            return None, e
        """

    # Callable with converter as a parameter
    def generate_source(self, msg, converter):
        try:
            proto_converter = converter(msg)
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
        self.failure_log = db_client["failure_log"]
        self.run_results = db_client["run_results"]

    def init_queue(self):
        self.qm = MultiQueueManager(queue_managers=[
            QueueManager(
                q_params["host"],
                q_params["port"],
                q_params["queue_name"],
                self.logger
            )
            for q_params in self.conf.compiler_queues])
