from runner_api import RunnerBase
from vyper.compiler.settings import Settings, OptimizationLevel

# Override class methods

class RunnerAdder(RunnerBase):
    def init_compiler_settings(self):
        compiler_settings = Settings(optimize=OptimizationLevel.from_string(
                    self.compiler_params["exec_params"]["optimization"]))
        self.comp_settings = {"settings": compiler_settings}


runner = RunnerAdder()

runner.start_runner()