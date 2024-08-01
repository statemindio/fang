import os

from pymongo import MongoClient


def get_mongo_client(host=None, port=None):
    return MongoClient(
        "mongodb://%s" % (host or os.environ.get("DB_HOST", "localhost")),
        port or int(os.environ.get("DB_PORT", 27017))
    )["my_queue"]
