## On host

### Periphery

To run minimal service set-up (the only compiler and generator and runner) it's required to run database and AMQ
instances.
Running DB:

```bash
docker run -d -p 27017:27017 mongo
```

AMQ:

```bash
docker run -d -p 5672:5672 -p 15672:15672 rabbitmq:management
```

So now the database and AMQ services are allowed by `localhost:27017` and `localhost:5672` respectively.

### Configuration

Since the periphery are run we need to put according configurations to `config.yml` file:

```yaml
compilers:
  - name: opt_codesize
    queue:
      host: localhost
      port: 5672
    exec_params:
      optimization: codesize
db:
  host: localhost
  port: 27017
```

### Running the Generator service

This part is written assuming all commands are run in virtual environment and all dependencies are installed:

```bash
pip install -r requirements.txt
```

Also, it's needed to compile `.proto`:

```bash
protoc  --python_out=./ ./vyperProto.proto
```

Since all dependencies are installed the services can be run:

```bash
python ./run.py
```

### Running the Compiler service

```bash
export PYTHONPATH=$(pwd)
SERVICE_NAME=opt_codesize python tests/integration_runner/compile.py
```

### Running the Runner service

```bash
export PYTHONPATH=$(pwd)
python runners/simple_runner.py
```