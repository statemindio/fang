import yaml

# -1 to remove max
MAX_NESTING_LEVEL = 3
MAX_EXPRESSION_LEVEL = 3
MAX_FUNCTION_INPUT = 5
MAX_FUNCTION_OUTPUT = 5
MAX_STORAGE_VARIABLES = 5
MAX_LOCAL_VARIABLES = 5
MAX_FUNCTIONS = 5
MAX_LIST_SIZE = 100
MAX_BYTESTRING_SIZE = 1000


class Config:
    def __init__(self, config_source_path="./config.yml"):
        with open(config_source_path) as csf:
            self.__config_source = yaml.safe_load(csf)

        self._compiler_queues = [
            dict(host=c["queue"]["host"], port=c["queue"]["port"], queue_name="queue3.10")
            for c in self.__config_source["compilers"]
        ]
        self._db = self.__config_source["db"]

    @property
    def compiler_queues(self):
        return self._compiler_queues

    @property
    def db(self):
        return self._db

    @property
    def compilers(self):
        return self.__config_source["compilers"]

    @property
    def input_strategies(self):
        return self.__config_source["input_strategies"]

    @property
    def verbosity(self):
        return self.__config_source["verbosity"]

    def get_compiler_params_by_name(self, name):
        for comp in self.__config_source["compilers"]:
            if comp["name"] == name:
                return comp
        return None
