import os

from pymongo import MongoClient


def get_mongo_client():
    return MongoClient(
        "mongodb://%s" % os.environ.get("DB_HOST", "localhost"),
        int(os.environ.get("DB_PORT", 27017))
    )["my_queue"]
