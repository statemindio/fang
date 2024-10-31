import logging
import time

from config import Config
from db import get_mongo_client

class VerifierException(Exception):
    pass

class VerifierBase:

    RUNTIME_ERROR = "runtime_error"

    def __init__(self, config_file=None):
        self.conf = Config(config_file) if config_file is not None else Config()
        self.init_logger()
        self.init_db()

    def start_verifier(self):
        while True:
            unhandled_results = list(self.results_collection.find({"is_handled": False}))
            self.logger.debug(f"Unhandled results received: {unhandled_results}")

            verification_results = []
            for res in unhandled_results:
                self.logger.info(f"Handling result: {res['generation_id']}")
                self.logger.debug(res)
                if not self.ready_to_handle(res):
                    self.logger.debug("%s is not ready yet", res["generation_id"])
                    continue

                if not self.is_valid(res):
                    continue

                has_errors, results = self.check_deploy_errors(res)
                if has_errors:
                    verification_results.append({"generation_id": res["generation_id"], "results": results})
                    continue

                reshaped_res = self.reshape_data(res)
                _r = self.verify_results(reshaped_res)
                verification_results.append({"generation_id": res["generation_id"], "results": _r})

            if len(verification_results) != 0:
                self.verification_results_collection.insert_many(verification_results)

            if len(unhandled_results) != 0:
                self.results_collection.update_many(
                    {"_id": {"$in": [r["_id"] for r in unhandled_results]}},
                    {"$set": {"is_handled": True}}
                )
            time.sleep(5)

    def check_deploy_errors(self, _res):
        deploy_errors = []
        fields = self.target_fields()

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
                verify_result = self.verify_and_catch(self.compilation_error_handler,
                                                    (errors[j], errors[j+1]))
                deploy_results.append({
                    "compilers": (fields[j], fields[j + 1]),
                    "deployment": i,
                    "results": verify_result
                })
        return has_error, deploy_results

    def reshape_data(self, _res):
        compilers = self.target_fields()
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

    def verify_results(self, data):
        compilers = self.target_fields()
        results = []
        for func_name, deployments in data.items():
            for i, depl in enumerate(deployments):
                for k, compilers_res in enumerate(depl):
                    for j, _res in enumerate(compilers_res):
                        if j == len(compilers_res) - 1:
                            break
                        d = self.verify_two_results(_res, compilers_res[j + 1])
                        results.append({
                            "compilers": (compilers[j], compilers[j + 1]),
                            "function": func_name,
                            "deployment": i,
                            "params_set": k,
                            "results": d
                        })
        return results

    def is_valid(self, _res):
        fields = self.target_fields()
        for f in fields:
            # contract is empty, regardless of inputs
            if len(_res[f][0]) == 0:
                return False
        return True

    def ready_to_handle(self, _res) -> bool:
        fields = self.target_fields()
        return all(f in _res for f in fields)

    # Must match run_results_collection setting in the runner callback
    def target_fields(self) -> list:
        return [f"result_{c['name']}" for c in self.conf.compilers]

    # Add new verifiers to the mapping
    def verify_two_results(self, _res0, _res1):
        if self.RUNTIME_ERROR in _res0 or self.RUNTIME_ERROR in _res1:
            self.runtime_error_handler(_res0, _res1)
            return {}
        verifiers = {
            "Storage": (self.storage_verifier, (_res0["state"], _res1["state"])),
            "Memory": (self.memory_verifier, (_res0["memory"], _res1["memory"])),
            "Gas": (self.gas_verifier, (_res0["consumed_gas"], _res1["consumed_gas"])),
            "Return_Value": (self.return_value_verifier, (_res0["return_value"], _res1["return_value"]))
        }
        d = {}
        for name, (verifier, params) in verifiers.items():
            d[name] = self.verify_and_catch(verifier, params)
        return d

    def verify_and_catch(self, verifier, params):
        try:
            verifier(*params)
            err = None
        except VerifierException as e:
            self.logger.error(str(e))
            err = str(e)
        return err

    # To change the verification logic override functions below
    def storage_verifier(self, storage0, storage1):
        if storage0 != storage1:
            raise VerifierException(f"Storage discrepancy: {storage0} | {storage1}")

    def memory_verifier(self, memory0, memory1):
        # TODO: come up with memory verification process
        # It seems like we won't me right to just compare this two values
        pass

    def gas_verifier(self, gas0, gas1):
        pass

    def return_value_verifier(self, value0, value1):
        loaded_value0 = value0
        loaded_value1 = value1
        if loaded_value0 != loaded_value1:
            raise VerifierException(f"Return Value discrepancy: {loaded_value0} | {loaded_value1}")

    def runtime_error_handler(self, _res0, _res1):
        # TODO: compare errors of both results
        pass

    def compilation_error_handler(self, _res0, _res1):
        if _res0 != _res1:
            raise VerifierException(f"Compilation error discrepancy: {_res0} | {_res1}")

    def init_logger(self):
        logger_level = getattr(logging, self.conf.verbosity)
        self.logger = logging.getLogger("verifier")
        logging.basicConfig(
            format='%(name)s:%(levelname)s:%(asctime)s:%(message)s', level=logger_level)
        self.logger.info("Starting verification")

    # results_collection matches run_results_collection from runner
    def init_db(self):
        db_client = get_mongo_client(self.conf.db["host"], self.conf.db["port"])
        self.results_collection = db_client["run_results"]
        self.verification_results_collection = db_client["verification_results"]
