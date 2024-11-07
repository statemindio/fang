# Fuzzing set-ups

Please note, that the `titanoboa` used in the fuzzer is a patched version of the original tool. 
The patch allows runners to extract the execution data such as storage, memory, etc.

The fuzzing set-ups to test the compiler keys require only one version of the `titanoboa`&`vyper`.
Meanwhile, cross-version fuzzing might require different environments to execute testing.

## The proto template

The proto template allows for targeted testing by enabling only relevant proto structures.

`protoc  --python_out=./ ./protoTemplate.proto`

## The venom fuzzing set-up:

Tests the compilation key `--experimental-codegen` (new IR).

`pip install -r requirements_nagini.txt`

This particular fuzzer consists of the following services:

1. Generator `fuzz/generators/run_nagini.py`
2. Two instances of runners `fuzz/runners/runner_ir.py`
	- The distinctions are configured via the compiler name provided as an environment variable and defined in the `config.yaml`
	- For `venom` testing `exec_params` of one of the services must be `venom: True`
3. Verifier `fuzz/verifiers/simple_verifier.py`
4. Proto template `vyperProtoNewNoDecimal.proto` 
	- Or `vyperProtoNew.proto` if decimals are enabled (`--enable-decimals`)

## The 0.3.10 optimizations fuzzing:

Tests compiler optimization modes `--optimize`.

`pip install -r requirements_adder.txt`

Consist of:

1. Generator `fuzz/generators/run_adder.py`
2. Two or Three instances of runners `fuzz/runners/runner_opt.py`
	- Takes the optimization keys from the `exec_params` field for each compiler in `config.yaml`
	- `optimization: gas` (default), `optimization: codesize`, `optimization: none`
3. Verifier `fuzz/verifiers/simple_verifier.py`
4. Proto template `vyperProtoNew.proto` 

## Cross-version fuzzing

Tests the vyper 0.4.0 against the 0.3.10, hence requires two versions of titanoboa in the set-up.
Aimed to uncover compiler regressions.

The cross-version fuzzing of versions with major changes entails certain caveats:

1. The coverage-guidance anchors on only one version (0.4.0 in this case)
2. Source codes are not compatible with each other, which means the generator has to produce two equivalent sources
3. The error reporting might significantly differ, which complicates the verification process

Two different environments:
- `pip install -r requirements_nagini.txt`
- `pip install -r requirements_adder.txt`

Consist of:
1. Generator `fuzz/generators/run_diff.py`.
2. Two instances of runners `fuzz/runners/runner_diff.py` in different environments
	- The 0.4.0 version does not have decimals by default, requires `extra_flags: ['enable_decimals']`
	- The differences are configured via the environment
3. Verifier `fuzz/verifiers/simple_verifier.py`
	- Will yield a lot of false positives, and requires additional filtering
4. Proto template `vyperProtoNew.proto` 