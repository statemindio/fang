from config import Config
from db import get_mongo_client

conf = Config()


def verify_results(_results):
    pass


if __name__ == '__main__':
    db_client = get_mongo_client(conf.db["host"], conf.db["port"])
    results_collection = db_client["run_results"]

    unhandled_results = results_collection.find({"is_handled": False})

    for res in unhandled_results:
        verify_results(res)
