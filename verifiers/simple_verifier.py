import json

from config import Config
from db import get_mongo_client

conf = Config()


class VerifierException(Exception):
    pass


def storage_verifier(storage0, storage1):
    if storage0 != storage1:
        raise VerifierException(f"Storage discrepancy: {storage0} | {storage1}")


def memory_verifier(memory0, memory1):
    # TODO: come up with memory verification process
    # It seems like we won't me right to just compare this two values
    pass


def gas_verifier(gas0, gas1):
    pass


def return_value_verifier(value0, value1):
    loaded_value0 = json.loads(value0)
    loaded_value1 = json.loads(value1)
    if loaded_value0 != loaded_value1:
        raise VerifierException(f"Return Value discrepancy: {loaded_value0} | {loaded_value1}")


def verify_two_results(_res0, _res1):
    storage_verifier(_res0["storage"], _res1["storage"])
    memory_verifier(_res0["memory"], _res1["memory"])
    gas_verifier(_res0["consumed_gas"], _res1["consumed_gas"])
    return_value_verifier(_res0["return_value"], _res1["return_value"])


def verify_results(_results):
    compilers = _results["results"].keys()
    for _res in zip(_results["results"][compiler_key] for compiler_key in compilers):
        for i, _func_res in enumerate(_res):
            if i == len(_res):
                break
            try:
                verify_two_results(_func_res, _res[i + 1])
            except VerifierException as e:
                # TODO: save discrepancy to db here
                pass


if __name__ == '__main__':
    db_client = get_mongo_client(conf.db["host"], conf.db["port"])
    results_collection = db_client["run_results"]

    unhandled_results = list(results_collection.find({"is_handled": False}))

    for res in unhandled_results:
        verify_results(res)

    results_collection.update_many(
        {"_id": {"$in": [r["_id"] for r in unhandled_results]}},
        {"$set": {"is_handled": True}}
    )
