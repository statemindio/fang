import json
import os
import logging

import pika.exceptions
import vyper
import boa
from vyper.compiler.settings import Settings, OptimizationLevel
from bson.objectid import ObjectId

from config import Config
from db import get_mongo_client
from json_encoders import ExtendedEncoder, ExtendedDecoder
from queue_managers import QueueManager


compiler_name = os.environ.get("SERVICE_NAME")

conf = Config("./config.yml")
compiler_params = conf.get_compiler_params_by_name(compiler_name)

compiler_key = f"{vyper.__version__.replace('.', '_')}_{compiler_name}"

logger_level = getattr(logging, conf.verbosity)
logger = logging.getLogger(f"runner_{compiler_key}")
logging.basicConfig(
    format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logger_level)
logger.info("Starting %s runner", compiler_key)

queue_name = 'queue3.10'
queue_params = conf.compiler_queues[compiler_params["queue"]]
qm = QueueManager(queue_params["host"], int(
    queue_params["port"]), queue_name, logger)
compiler_settings = Settings(optimize=OptimizationLevel.from_string(
    compiler_params["exec_params"]["optimization"]))

channel = qm.channel

db_ = get_mongo_client(conf.db["host"], conf.db["port"])
queue_collection = db_["compilation_log"]
run_results_collection = db_["run_results"]

inputs_per_function = len(conf.input_strategies)

def callback(ch, method, properties, body):
    data = json.loads(body)

    logger.debug("Compiling contract id: %s", data["_id"])

    result = handle_compilation(data)
    logger.debug("Compilation and execution result: %s", result)

    queue_collection.update_one({"_id": ObjectId(data["_id"])},
                                {"$set": {f"compiled_{compiler_key}": True}})
    run_results_collection.update_one({"generation_id": data["_id"]},
                                      {"$set": {f"result_{compiler_key}": result, "is_handled": False}})

# Init values might affect state, so for every init_values bundle
# We run function payloads separately
# Though same applies for regular functions too
# Every call after the first one will work with already affected state
def handle_compilation(_contract_desc):
    input_values = json.loads(
        _contract_desc["function_input_values"], cls=ExtendedDecoder)
    init_values = input_values.get("__init__", [[]])

    results = []
    for iv in init_values:
        logger.debug("Constructor values: %s", iv)
        try:
            contract = boa.loads(_contract_desc["generation_result"],
                                 *iv, compiler_args={"settings": compiler_settings})
        except Exception as e:
            logger.debug("Deployment failed: %s", str(e))
            results.append(dict(deploy_error=str(e)))
            continue

        _r = dict()
        externals = [c for c in dir(contract) if c.startswith('func')]
        internals = [c for c in dir(contract.internal) if c.startswith('func')]
        for fn in externals:
            function_call_res = []
            _r[fn] = [execution_result(contract, fn, input_values[fn][i])
                      for i in range(inputs_per_function)]

        for fn in internals:
            function_call_res = []
            _r[fn] = [execution_result(
                      contract, fn, input_values[fn][i], internal=True)
                      for i in range(inputs_per_function)]

        fn = "__default__"
        if fn in dir(contract):
            function_call_res = [execution_result(contract, fn, [])
                                 for i in range(inputs_per_function)]
            _r[fn] = function_call_res
        results.append(_r)
    return results


def execution_result(_contract, fn, _input_values, internal=False):
    try:
        logger.debug("calling %s with calldata: %s", fn, _input_values)
        if internal:
            computation, res = getattr(_contract.internal, fn)(*_input_values)
        else:
            computation, res = getattr(_contract, fn)(*_input_values)
        logger.debug("%s result: %s", fn, res)
        _function_call_res = compose_result(_contract, computation, res)
    except Exception as e:
        res = str(e)
        logger.debug("%s caught error: %s", fn, res)
        _function_call_res = dict(runtime_error=res)
    return _function_call_res

# TODO: Perhaps we can save immutables info
def compose_result(_contract, comp, ret) -> dict:
    # now we dump first ten slots only
    state = [str(comp.state.get_storage(bytes.fromhex(
        _contract.address[2:]), i)) for i in range(10)]

    # first 1280 bytes are dumped
    memory = comp.memory_read_bytes(0, 1280).hex()

    consumed_gas = comp.get_gas_used()
    # The order of function calls is the same for all runners
    # Adding the name just to know what result is checked
    return dict(state=state, memory=memory, consumed_gas=consumed_gas, return_value=json.dumps(ret, cls=ExtendedEncoder))


while True:
    try:
        channel.basic_consume(
            queue_name, on_message_callback=callback, auto_ack=True)
        channel.start_consuming()
    except (pika.exceptions.StreamLostError, pika.exceptions.ChannelWrongStateError):
        pass
