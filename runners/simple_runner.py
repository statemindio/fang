import contextlib
import json
import pickle
import sys
import time
from collections import defaultdict

import boa
import eth.exceptions
import vyper

sys.path.append('.')
import types_d

from config import Config
from db import get_mongo_client

sender = ""  # TODO: init actual sender address


class ContractsProvider:
    def __init__(self, db_connector, name):
        self._source = db_connector
        self._name = name

    @property
    def name(self):
        return self._name

    @contextlib.contextmanager
    def get_contracts(self):
        contracts = self._source.find({"ran": False})
        contracts = list(contracts)
        yield contracts
        self._source.update_many(
            {'_id': {'$in': [c['_id'] for c in contracts]}},
            {'$set': {'ran': True}}
        )


def get_input_params(gen_types):
    values = []
    print(gen_types)
    for typ in gen_types:
        val = []
        if isinstance(typ, types_d.FixedList):
            val.append(get_input_params([typ.base_type for i in range(typ.size)]))
            # for i in range(typ.size):
            # val.append(typ.base_type.generate())
        else:
            val = typ.generate()
        values.append(val)
    return values


def external_nonpayable_runner(contract, abi_func, gen_types):
    func = getattr(contract, abi_func["name"])
    decoded_types = pickle.loads(bytes.fromhex(gen_types))
    input_params = get_input_params(decoded_types[abi_func["name"]])
    computation, output = func(*input_params)
    return computation, output


def compose_result(comp, ret) -> dict:
    # now we dump first ten slots only
    state = [str(comp.state.get_storage(bytes.fromhex(contract.address[2:]), i)) for i in range(10)]

    # first 1280 bytes are dumped
    memory = comp.memory_read_bytes(0, 1280).hex()

    consumed_gas = comp.get_gas_used()

    return dict(state=state, memory=memory, consumed_gas=consumed_gas, return_value=json.dumps(ret))


def save_results(res):
    to_save = [{"generation_id": gid, "results": results} for gid, results in res.items()]
    if len(to_save) == 0:
        print("No results to save...")
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
def execution_result(_contract, _abi_item, gen_types):
    comp, ret = external_nonpayable_runner(_contract, _abi_item, gen_types)
    _function_call_res = compose_result(comp, ret)
    return _function_call_res


def deploy_bytecode(_contract_desc):
    if "bytecode" not in _contract_desc:
        return None
    try:
        at, _ = boa.env.deploy_code(
            bytecode=bytes.fromhex(contract_desc["bytecode"][2:])
        )

        factory = boa.loads_abi(json.dumps(contract_desc["abi"]), name="Foo")
        _contract = factory.at(at)
        return _contract
    except eth.exceptions.Revert as e:
        # TODO: log the exception into db
        print("deployment failed: ", str(e), _contract_desc, flush=True)
        return None


if __name__ == "__main__":
    conf = Config()

    db_contracts = get_mongo_client(conf.db["host"], conf.db["port"])

    run_results_collection = db_contracts["run_results"]

    collections = [
        f"compilation_results_{vyper.__version__.replace('.', '_')}_{c['name']}" for c in conf.compilers
    ]
    print("Collections: ", collections, flush=True)
    contracts_cols = (db_contracts[col] for col in collections)

    contracts_providers = [
        ContractsProvider(contracts_col, f"{vyper.__version__}_{c['name']}")
        for contracts_col, c in zip(contracts_cols, conf.compilers)
    ]
    reference_amount = len(collections)

    while True:
        interim_results = defaultdict(list)
        for provider in contracts_providers:
            with provider.get_contracts() as contracts:
                print(f"Amount of contracts: ", len(contracts), flush=True)
                for contract_desc in contracts:
                    contract = deploy_bytecode(contract_desc)
                    if contract is None:
                        continue
                    r = []
                    for abi_item in contract_desc["abi"]:
                        if abi_item["type"] == "function" and abi_item["stateMutability"] == "nonpayable":
                            function_call_res = execution_result(
                                contract,
                                abi_item,
                                contract_desc["function_input_types"]
                            )
                            r.append(function_call_res)
                    interim_results[contract_desc["generation_id"]].append({provider.name: r})
            print("interim results", interim_results, flush=True)
        results = dict((_id, res) for _id, res in interim_results.items() if len(res) == reference_amount)
        print("results", results, flush=True)
        save_results(results)

        print("waiting....", flush=True)
        time.sleep(2)  # wait two seconds before the next request
