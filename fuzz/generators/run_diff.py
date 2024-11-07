import atheris
from google.protobuf.json_format import MessageToJson

from run_api import GeneratorBase

with atheris.instrument_imports():
    import vyper
    from fuzz.converters.typed_converters import TypedConverter
    from fuzz.converters.typed_converters_4 import NaginiConverter


class GeneratorDiff(GeneratorBase):
    def __init__(self, proto_converter, proto_converter_diff, config_file=None):
        GeneratorBase.__init__(self, proto_converter, config_file)
        self.converter_diff = proto_converter_diff

    def TestOneProtoInput(self, msg):
        data = {
            "json_msg": MessageToJson(msg),
            "generation_result_nagini": None,
            "generation_result_adder": None,
            "compilation_result": None,
            "error_type": None,
            "error_message": None,
            "generator_version": self.__version__,
        }
        proto_converter = self.generate_source(msg, self.converter)
        proto_converter_diff = self.generate_source(msg, self.converter_diff)
        # add other compiler results 
        data["generation_result_nagini"] = proto_converter.result
        data["generation_result_adder"] = proto_converter_diff.result

        c_result, c_error = self.compile_source(proto_converter.result)
        if c_error is None:
            data["compilation_result"] = c_result
        else:
            data["error_type"] = type(c_error).__name__
            data["error_message"] = str(c_error)

        self.logger.debug("Compilation result: %s", data)

        input_values = self.generate_inputs(proto_converter.function_inputs)
        self.logger.debug("Generated inputs: %s", input_values)
        data["function_input_values"] = input_values

        insert = self.compilation_log.insert_one(data)

        message = {
            "_id": str(insert.inserted_id),
            "generation_result_nagini": proto_converter.result,
            "generation_result_adder": proto_converter_diff.result,
            "function_input_values": input_values,
            "json_msg": MessageToJson(msg),
            "generator_version": self.__version__,
        }
        self.qm.publish(**message)

        # Creating the result entry, so there's no race condition in runners
        self.run_results.insert_one({'generation_id': str(insert.inserted_id)})

    def compile_source(self, proto_result):
        try:
            c_result = vyper.compile_code(proto_result)
            return c_result, None
        except Exception as e:
            return None, e


generator = GeneratorDiff(NaginiConverter, TypedConverter)

if __name__ == '__main__':
    generator.start_generator()
