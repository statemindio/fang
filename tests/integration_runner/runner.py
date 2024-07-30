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
from json_encoders import ExtendedDecoder
from queue_managers import QueueManager


compiler_name = os.environ.get("SERVICE_NAME")

conf = Config("./config.yml")
compiler_params = conf.get_compiler_params_by_name(compiler_name)

compiler_key = f"{vyper.__version__.replace('.', '_')}_{compiler_name}"

# TODO: get level from config
logger = logging.getLogger(f"runner_{compiler_key}")
logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logging.INFO)
logger.info("Starting %s runner", compiler_key)

queue_name = 'queue3.10'
qm = QueueManager(compiler_params["queue"]["host"], int(compiler_params["queue"]["port"]), queue_name, logger)
compiler_settings = Settings(optimize=OptimizationLevel.from_string(compiler_params["exec_params"]["optimization"]))

channel = qm.channel

db_ = get_mongo_client(conf.db["host"], conf.db["port"])
queue_collection = db_["compilation_log"]
run_results_collection = db_["run_results"]


def callback(ch, method, properties, body):
    data = json.loads(body)
    # print(data["_id"])
    logger.debug("Compiling contract id: %s", data["_id"])

    result = handle_compilation(data)
    logger.debug("Compilation and execution result: %s", result)

    queue_collection.update_one({"_id": ObjectId(data["_id"])},
                                {"$set": {f"compiled_{compiler_key}": True}})
    run_results_collection.update_one({"generation_id": data["_id"]},
                                        {"$set": {f"result_{compiler_key}": result}})


def compose_result(_contract, comp, ret) -> dict:
    # now we dump first ten slots only
    state = [str(comp.state.get_storage(bytes.fromhex(_contract.address[2:]), i)) for i in range(10)]

    # first 1280 bytes are dumped
    memory = comp.memory_read_bytes(0, 1280).hex()

    consumed_gas = comp.get_gas_used()

    return dict(state=state, memory=memory, consumed_gas=consumed_gas, return_value=json.dumps(ret))


def execution_result(_contract, fn, _input_values):
    try:
        res = getattr(_contract, fn)(*_input_values)
        _function_call_res = compose_result(_contract, _contract._computation, res)
    except Exception as e:
        res = str(e)
        _function_call_res = dict(error = res)
    return _function_call_res


def deploy_contract(_source, _init_values):
    try:
        _contract = boa.loads(_source, *_init_values, compiler_args = {"settings": compiler_settings})
        return _contract
    except Exception as e:
        # catch compilation errors as well as runtime
        # TODO: maybe distinguish runtime from compilation
        logger.debug("Deployment failed: %s", str(e))
        return str(e)


def handle_compilation(_contract_desc):
    input_values = json.loads(_contract_desc["function_input_values"], cls=ExtendedDecoder)
    init_values = input_values.get("__init__", [])
    contract = deploy_contract(_contract_desc["generation_result"], init_values)

    # TODO: can it be more meaningful than error string?
    if isinstance(contract, str):
        return contract

    _r = []
    externals = [c for c in dir(contract) if c.startswith('func') ]
    internals = [c for c in dir(contract.internal) if c.startswith('func') ]
    for funcs in (externals, internals):
        for fn in funcs:
            function_call_res = execution_result(contract, fn, init_values[fn])
            _r.append(function_call_res)
    return _r

while True:
    try:
        channel.basic_consume(queue_name, on_message_callback=callback, auto_ack=True)
        channel.start_consuming()
    except (pika.exceptions.StreamLostError, pika.exceptions.ChannelWrongStateError):
        pass
