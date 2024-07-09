import json
from collections import defaultdict

import boa

from db import get_mongo_client

sender = ""  # TODO: init actual sender address


class ContractsProvider:
    def __init__(self, db_connector):
        self._source = db_connector

    def get_contracts(self):
        contracts = self._source.find({"ran": False})
        return contracts


def get_input_params(types):
    # TODO: implement
    return []


def external_nonpayable_runner(contract, abi_func):
    func = getattr(contract, abi_func["name"])
    input_params = get_input_params(abi_func["inputs"])
    computation, output = func(*input_params)
    return computation, output


def compose_result(comp, ret) -> dict:
    # now we dump first ten slots only
    state = [comp.state.get_storage(bytes.fromhex(contract.address[2:]), i) for i in range(10)]

    # first 1280 bytes are dumped
    memory = comp.memory_read_bytes(0, 1280).hex()

    consumed_gas = comp.get_gas_used()

    return dict(state=state, memory=memory, consumed_gas=consumed_gas, return_value=ret)


db_contracts = get_mongo_client()

run_results_collection = db_contracts["run_results"]


def save_results(res):
    for gid, results in res.items():
        run_results_collection.insert_many({"generation_id": gid, "results": results})


if __name__ == "__main__":
    collections = (
        'compilation_results_0_3_10_codesize',
        'compilation_results_0_3_10_gas',
    )
    contracts_cols = (db_contracts[col] for col in collections)
    contracts_providers = (ContractsProvider(contracts_col) for contracts_col in contracts_cols)
    reference_amount = len(collections)
    interim_results = defaultdict(list)
    for provider in contracts_providers:
        contracts = provider.get_contracts()
        for contract_desc in contracts:
            at, _ = boa.env.deploy_code(
                bytecode=bytes.fromhex(contract_desc["bytecode"][2:])
            )

            factory = boa.loads_abi(json.dumps(contract_desc["abi"]), name="Foo")
            contract = factory.at(at)
            for abi_item in contract_desc["abi"]:
                if abi_item["type"] == "function" and abi_item["stateMutability"] == "nonpayable":
                    comp, ret = external_nonpayable_runner(contract, abi_item)

                    # well, now we save some side effects as json since it's not
                    # easy to pickle an object of abc.TitanoboaComputation
                    function_call_res = compose_result(comp, ret)
                    interim_results[contract_desc["_id"]].append(function_call_res)
    results = dict((_id, res) for _id, res in interim_results.items() if len(res) == reference_amount)
    save_results(results)
