from config import Config
from db import get_mongo_client

conf = Config()


def verify_two_results(_res0, _res1):
    # TODO: call low lever verifiers here
    pass


def verify_results(_results):
    compilers = _results["results"].keys()
    for _res in zip(_results["results"][compiler_key] for compiler_key in compilers):
        for i, _func_res in enumerate(_res):
            if i == len(_res):
                break
            verify_two_results(_func_res, _res[i + 1])


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
