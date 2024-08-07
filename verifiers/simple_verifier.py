import logging
import time

from config import Config
from db import get_mongo_client

# TODO: get level from config
logger = logging.getLogger("verifier")
logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logging.DEBUG)


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
    loaded_value0 = value0
    loaded_value1 = value1
    if loaded_value0 != loaded_value1:
        raise VerifierException(f"Return Value discrepancy: {loaded_value0} | {loaded_value1}")


def runtime_error_handler(_res0, _res1):
    # TODO: compare errors of both results
    pass


RUNTIME_ERROR = "runtime_error"


def verify_two_results(_res0, _res1):
    if RUNTIME_ERROR in _res0 or RUNTIME_ERROR in _res1:
        runtime_error_handler(_res0, _res1)
        return {}
    verifiers = {
        "Storage": (storage_verifier, (_res0["state"], _res1["state"])),
        "Memory": (memory_verifier, (_res0["memory"], _res1["memory"])),
        "Gas": (gas_verifier, (_res0["consumed_gas"], _res1["consumed_gas"])),
        "Return_Value": (return_value_verifier, (_res0["return_value"], _res1["return_value"]))
    }
    d = {}
    for name, (verifier, params) in verifiers.items():
        try:
            verifier(*params)
            d[name] = None
        except VerifierException as e:
            d[name] = str(e)
            continue
    return d


def verify_results(_conf: Config, data):
    compilers = target_fields(_conf)
    results = []
    for func_name, deployments in data.items():
        for i, depl in enumerate(deployments):
            for compilers_res in depl:
                for j, _res in compilers_res:
                    if j == len(compilers_res) - 1:
                        break
                    d = verify_two_results(_res, _res[j + 1])
                    results.append({
                        "compilers": (compilers[j], compilers[j + 1]),
                        "function": func_name,
                        "deployment": i,
                        "results": d
                    })
    return results


def target_fields(_conf: Config) -> list:
    return [f"result_{c['name']}" for c in _conf.compilers]


def ready_to_handle(_conf: Config, _res) -> bool:
    fields = target_fields(_conf)
    return all(f in _res for f in fields)


def reshape_data(_conf, _res):
    compilers = target_fields(_conf)
    result = {}

    for i, compiler in enumerate(compilers):
        compiler_data = compilers[compiler]
        for j, depl in enumerate(compiler_data):
            for func_name, results in depl.items():
                if func_name not in results:
                    result[func_name] = []
                if j > len(result[func_name]) - 1:
                    result[func_name].append([])
                for k, r in enumerate(results):
                    if k > len(result[func_name][j]) - 1:
                        result[func_name][j].append([])
                    result[func_name][j][k].append(r)

    return result


def is_valid(_conf, _res):
    fields = target_fields(_conf)
    for f in fields:
        if len(_res[f][0]) == 0:
            return False
        if "deploy_error" in _res[f][0]
            return False
    return True


if __name__ == '__main__':
    conf = Config()
    db_client = get_mongo_client(conf.db["host"], conf.db["port"])
    results_collection = db_client["run_results"]
    verification_results_collection = db_client["verification_results"]

    while True:
        unhandled_results = list(results_collection.find({"is_handled": False}))
        logger.debug(f"Unhandled results received: {unhandled_results}")

        verification_results = []
        for res in unhandled_results:
            logger.info(f"Handling result: {res['generation_id']}")
            logger.debug(res)
            if not ready_to_handle(conf, res):
                logger.debug("%s is not ready yet", res["generation_id"])
                continue

            if not is_valid(conf, res):
                continue
            reshaped_res = reshape_data(conf, res)
            _r = verify_results(conf, reshaped_res)
            verification_results.append({"generation_id": res["generation_id"], "results": _r})

        if len(verification_results) != 0:
            verification_results_collection.insert_many(verification_results)

        if len(unhandled_results) != 0:
            results_collection.update_many(
                {"_id": {"$in": [r["_id"] for r in unhandled_results]}},
                {"$set": {"is_handled": True}}
            )
        time.sleep(5)
