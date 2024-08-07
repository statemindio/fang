import contextlib
import json
import pickle
import time
import logging
from collections import defaultdict

import boa
import eth.exceptions
import vyper
from boa.contracts.abi.abi_contract import ABIFunction

from config import Config
from db import get_mongo_client
from json_encoders import ExtendedDecoder

sender = ""  # TODO: init actual sender address


class ContractsProvider:
    def __init__(self, db_connector, name):
        self._source = db_connector
        self._name = name

    @property
    def name(self):
        return self._name

    def get_contracts(self):
        _contracts = self._source.find({"ran": False})
        _contracts = list(_contracts)
        return _contracts

    def mark_as_run_by_generation_ids(self, _ids):
        self._source.update_many(
            {'generation_id': {'$in': _ids}},
            {'$set': {'ran': True}}
        )


def external_nonpayable_runner(contract, function_name, input_values):
    func = getattr(contract, function_name)
    input_params = input_values[function_name]
    computation, output = func(*input_params)
    return computation, output


def compose_result(_contract, comp, ret) -> dict:
    # now we dump first ten slots only
    state = [str(comp.state.get_storage(bytes.fromhex(_contract.address[2:]), i)) for i in range(10)]

    # first 1280 bytes are dumped
    memory = comp.memory_read_bytes(0, 1280).hex()

    consumed_gas = comp.get_gas_used()

    return dict(state=state, memory=memory, consumed_gas=consumed_gas, return_value=json.dumps(ret))


def save_results(res):
    to_save = [{"generation_id": gid, "results": _results} for gid, _results in res.items()]
    if len(to_save) == 0:
        logger.debug("No results to save...")
        return
    run_results_collection.insert_many(to_save)


def skip_execution_errors(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception:
            return dict(state=None, memory=None, consumed_gas=None, return_value=None)

    return wrapper


@skip_execution_errors
def execution_result(_contract, function_name, input_values):
    comp, ret = external_nonpayable_runner(_contract, function_name, input_values)
    _function_call_res = compose_result(_contract, comp, ret)
    return _function_call_res


def encode_init_inputs(contract_abi, args):
    for func in contract_abi:
        if func["type"] == "constructor":
            init_abi = func
            break
    # Otherwise will throw an error
    init_abi["name"] = "__init__"
    init_function = ABIFunction(init_abi, contract_name="__init__")

    return init_function.prepare_calldata(*args)[4:]


def deploy_bytecode(_contract_desc, _input_values):
    if "bytecode" not in _contract_desc:
        return None
    try:
        # relies on generator data
        init_values = _input_values.get("__init__", None)
        encoded_inputs = b''
        if init_values is not None:
            encoded_inputs = encode_init_inputs(_contract_desc["abi"], init_values)
        at, _ = boa.env.deploy_code(
            bytecode=bytes.fromhex(_contract_desc["bytecode"][2:]) + encoded_inputs
        )

        factory = boa.loads_abi(json.dumps(_contract_desc["abi"]), name="Foo")
        _contract = factory.at(at)
        return _contract
    except eth.exceptions.Revert as e:
        # TODO: log the exception into db
        # failed deployment is normal course of action
        logger.debug("Deployment failed: %s; %s", str(e), _contract_desc)
        return None


def handle_compilation(_contract_desc):
    input_values = json.loads(_contract_desc["function_input_values"], cls=ExtendedDecoder)
    contract = deploy_bytecode(_contract_desc, input_values)
    if contract is None:
        return None
    _r = []
    for abi_item in _contract_desc["abi"]:
        if abi_item["type"] == "function" and \
                abi_item["stateMutability"] in ("nonpayable", "view", "pure"):
            function_call_res = execution_result(
                contract,
                abi_item["name"],
                input_values
            )
            _r.append(function_call_res)
    return _r


if __name__ == "__main__":
    conf = Config()

    logger_level = getattr(logging, conf.verbosity)
    logger = logging.getLogger("runner")
    logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logger_level)

    db_contracts = get_mongo_client(conf.db["host"], conf.db["port"])

    run_results_collection = db_contracts["run_results"]

    collections = [
        f"compilation_results_{vyper.__version__.replace('.', '_')}_{c['name']}" for c in conf.compilers
    ]
    logger.info("Target collections: %s", collections)
    contracts_cols = (db_contracts[col] for col in collections)

    contracts_providers = [
        ContractsProvider(contracts_col, f"{vyper.__version__}_{c['name']}")
        for contracts_col, c in zip(contracts_cols, conf.compilers)
    ]
    reference_amount = len(collections)

    while True:
        interim_results = defaultdict(list)
        for provider in contracts_providers:
            contracts = provider.get_contracts()
            logger.info("Amount of contracts: %s", len(contracts))
            for contract_desc in contracts:
                logger.info("Handling compilation: %s", contract_desc["_id"])
                r = handle_compilation(contract_desc)
                interim_results[contract_desc["generation_id"]].append({provider.name: r})
            logger.debug("Interim results: %s", interim_results)
        results = dict((_id, res) for _id, res in interim_results.items() if len(res) == reference_amount)
        logger.debug("Results: %s", results)
        save_results(results)
        for provider in contracts_providers:
            provider.mark_as_run_by_generation_ids([generation_id for generation_id in results])

        logger.debug("Waiting (2 sec)")
        time.sleep(2)  # wait two seconds before the next request
