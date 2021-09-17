# Simulation-as-a-Service (SaaS) Middleware Developer Resources

## Exceptions Guidelines
 
### Error handling
The SaaS Middleware supports different interfaces/entrypoints, HTTP and CLI.  
The main SaaS code (usually found in `service.py` files) SHOULD report errors to the interfaces by throwing exceptions. This shifts the responsibility of handling errors to the interfaces, so that the they can decide on the appropriate response, such as returning an appropriate error message or returning an appropriate null value.

e.g.
```python
# SaaS codes
class SaaSService:
    def do_something(value: str) -> int:
        if value != "a": # Some kind of specific error
            raise ValueError("value is not a") # Raise exception here
        return 123

# Entrypoints
app = SaaSService()
value = "abc"

def HTTPEntrypoint():
    try:
        result = app.do_something(value)
    except ValueError as e: # Handle exception here
        logger.error(e) # Client wants to log
        result = 0 # Client wants 0 if error

def CLIEntrypoint():
    try:
        result = app.do_something(value)
    except ValueError as e: # Handle exception here
        result = None # Client wants None if error
```

When throwing exceptions in SaaS code, exceptions SHOULD try to be as specific as possible and avoid using the builtin "catchall" base `Exception` class.

Exceptions SHOULD come with a useful and easy to read message that describes the error so that a non-technical user could easily understand it.  
e.g. `'key' not found in 'dict' object` vs `Input JSON file is missing the property 'key'`.

A base exception class `SaaSException` is defined to support exceptions thrown from SaaS code. Any custom exceptions defined in the SaaS code MUST inherit from `SaaSException` and each SaaS service SHOULD define its own exceptions from it.

It is RECOMMENDED to use custom exceptions instead of the python builtin exceptions, to store extra information such as custom variables or stack trace to the exception instance.

### Exception Hierarchy
`SaaSException`
- `DORException`
  - `ObjectNotFoundError`
  - `InvalidDescriptorError`
  - `GPPError`
    - `RepositoryCreationError`
    - `DescriptorNotFoundError`
- `RTIException`
  - `ProcessorError`
    - `DeploymentError`
      - `StartupError`
      - `ShutdownError`
    - `ExecutionError`
- `NodeDBException`
  - `TransactionError`
  - `NetworkError`
- `MessengerException`
  - `InvalidProtcolError`
  - `PeerUnavailableError` 
  - `InvalidAddressError`
- `CryptographyException`
    - `InvalidKeyError`
    - `InvalidSignatureError`


## Logging Guidelines
The SaaS Middleware uses the default [logging facility of Python](https://docs.python.org/3/library/logging.html).

### Log Levels
Logging defines a number of default [logging levels](https://docs.python.org/3/library/logging.html#levels). Although 
it is possible to define custom logging levels, it is RECOMMENDED to use default logging levels only. If necessary, a 
TRACE logging level may be introduced to allow for more detailed output for debugging purposes.

Meaning and usage of logging levels:

- `CRITICAL` and `ERROR`: MUST only be used for exceptions, i.e., in case the normal workflow cannot continue. The log 
  entry SHOULD be made at the location where the exception is caught/handled, not where the exception is thrown/created.
  CRITICAL log level is reserved for exceptions that cause the application to crash, i.e., for conditions that leave the
  application in a state in which it cannot recover or continue to function and thus requiring a restart. Exceptions 
  SHOULD come with a stack trace and a unique id, both of which MUST be mentioned in the log message. Stack traces 
  SHOULD be logged using DEBUG log level, reflecting the reference id of the exception.

- `WARNING`: SHOULD be used for conditions that may cause a modification, but not a complete disruption, of the normal 
  workflow. Warnings SHOULD be used to highlight situations/conditions that are unexpected or pointing at a potential 
  problem. Unlike error/critical logs, warning logs MUST be made where they occur. 

- `INFO`: SHOULD be used to provide useful and meaningful information, allowing a system administrator or technical user
  to understand the progress of the normal workflow. In a production environment, this SHOULD be the default level.

- `DEBUG`: MUST provide technical information at sufficient level of detail to allow developers understand the nature of
  problems and to support the debugging process. Any information that is too technical or detailed to be logged as 
  info-level message, MUST be logged as debug message. In a development environment, this SHOULD be the default level.

- `NOTSET`: Not used.


### Destination
It MUST be possible to enable/disable writing logs to stderr and to write logs to one or more files. Furthermore, it 
SHOULD be possible to filter (e.g., by module name) and redirect logs to different files. In order to avoid extremely 
large log files, log files MUST be automatically rolled over once they have reached a certain size.


### Format
The formatting of logging messages SHOULD be human- and machine-readable. The following information MUST be 
contained by any log message:
- Human-readable Timestamp: timestamp (using UTC) formatted as `YY-mm-dd HH:MM:SS.fff`.
- Log level: the log level in capital letters, i.e., `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG`.
- Module name: the name of the module that created this message.
- Message: the message itself may be structured flexibly according to the needs by the module to increase 
  human/machine readability.

Example:
```
2021-09-09 07:27:37.244 [INFO] [cli] This is a example message. All is good!
```
