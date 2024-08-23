import logging
import time

from config import Config
from db import get_mongo_client

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


def compilation_error_handler(_res0, _res1):
    if _res0 != _res1:
        raise VerifierException(f"Compilation error discrepancy: {_res0} | {_res1}")

RUNTIME_ERROR = "runtime_error"


def verify_and_catch(verifier, params):
    try:
        verifier(*params)
        err = None
    except VerifierException as e:
        logger.error(str(e))
        err = str(e)
    return err


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
        d[name] = verify_and_catch(verifier, params)
    return d


def verify_results(_conf: Config, data):
    compilers = target_fields(_conf)
    results = []
    for func_name, deployments in data.items():
        for i, depl in enumerate(deployments):
            for k, compilers_res in enumerate(depl):
                for j, _res in enumerate(compilers_res):
                    if j == len(compilers_res) - 1:
                        break
                    d = verify_two_results(_res, compilers_res[j + 1])
                    results.append({
                        "compilers": (compilers[j], compilers[j + 1]),
                        "function": func_name,
                        "deployment": i,
                        "params_set": k,
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
        compiler_data = _res[compiler]
        for j, depl in enumerate(compiler_data):
            for func_name, results in depl.items():
                if func_name not in result:
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
        # contract is empty, regardless of inputs
        if len(_res[f][0]) == 0:
            return False
    return True

def check_deploy_errors(_conf, _res):
    deploy_errors = []
    fields = target_fields(_conf)

    has_error = False
    # reshaping: init->[compilers]
    for f in fields:
        for j, depl in enumerate(_res[f]):
            if j > len(deploy_errors) - 1:
                deploy_errors.append([])
            deploy_errors[j].append(_res[f][j].get("deploy_error", None))
            if deploy_errors[j][-1] is not None:
                has_error = True

    deploy_results = []
    for i, errors in enumerate(deploy_errors):
        for j, error in enumerate(errors):
            if j == len(errors) - 1:
                break
            verify_result = verify_and_catch(compilation_error_handler, 
                                                (errors[j], errors[j+1]))
            deploy_results.append({
                "compilers": (fields[j], fields[j + 1]),
                "deployment": i,
                "results": verify_result
            })
    return has_error, deploy_results


if __name__ == '__main__':
    conf = Config()

    logger_level = getattr(logging, conf.verbosity)
    logger = logging.getLogger("verifier")
    logging.basicConfig(format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logger_level)
    logger.info("Starting verification")
    
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

            has_errors, results = check_deploy_errors(conf, res)
            if has_errors:
                verification_results.append({"generation_id": res["generation_id"], "results": results})
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
