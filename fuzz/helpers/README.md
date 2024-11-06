# Helpers


## Scope

- [`config.py`](config.py): Manages project configuration. Key configuration parameters, such as maximum nesting levels and function constraints, are set here to control the complexity of generated tests.

- [`db.py`](db.py): Defines `get_mongo_client`, which connects to a `MongoDB` instance using parameters from the environment or configuration.

- [`json_encoders.py`](json_encoders.py): Contains custom `JSON` encoding/decoding classes, which handle special data types like `Decimal` and `bytes` that are not directly `JSON`-compatible.

- [`proto_helpers.py`](proto_helpers.py): Implements `ConvertFromTypeMessageHelper`

- [`proto_loader.py`](proto_loader.py): Dynamically loads `protobuf` definitions based on the current `Vyper` version and configuration settings.

- [`queue_managers.py`](queue_managers.py): Manages `RabbitMQ` connections and message queues through the QueueManager class.