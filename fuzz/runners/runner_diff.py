import os
from runner_api import RunnerBase


# Override class methods

class RunnerDiff(RunnerBase):
    def generation_result(self):
        return f"generation_result_{self.compiler_key}"

    def init_compiler_settings(self):
        if self.compiler_key == "nagini":
            RunnerBase.init_compiler_settings(self)
            return
        else:
            from vyper.compiler.settings import Settings, OptimizationLevel
            compiler_settings = Settings(optimize=OptimizationLevel.from_string(
                self.compiler_params["exec_params"]["optimization"]))
            self.comp_settings = {"settings": compiler_settings}


runner = RunnerDiff()

runner.start_runner()
