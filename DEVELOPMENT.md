# Simulation-as-a-Service (SaaS) Middleware Developer Resources

## Exceptions Guidelines
Exceptions SHOULD be used throughout the code instead of using return codes to indicate errors that cause the normal
flow of operation to be unable to continue. Exceptions SHOULD be handled on an appropriate level in the system
hierarchy. In particular, interfaces MUST handle exceptions.  This includes the CLI subsystem (which is a user 
interface) and the REST subsystem which is an API. The REST API needs to translate exceptions that occur during the
execution of an API function into a corresponding result that provides sufficient information to the caller to 
identify what the problem is. 

### Error handling
When raising exceptions, they SHOULD be as specific as possible and avoid using the builtin "catchall" base `Exception` 
or similarly unspecific types. Exceptions SHOULD come with a useful and easy to read message that describes the error 
so that a non-technical user could easily understand it. For example, `'key' not found in 'dict' object` vs `Input JSON 
file is missing the property 'key'`.

A base exception class `SaaSException` is defined to support any exceptions raised by the SaaS code. Any custom 
exceptions defined in the SaaS code MUST inherit from `SaaSException`. Each subsystem SHOULD define its own
subsystem-wide baseclass and corresponding specific exception types. It is RECOMMENDED to use custom exceptions 
instead of the Python builtin exceptions, to store extra information such as custom variables or stack trace to the 
exception instance.

### SaaSException
`SaaSException` is the base class for all exceptions in the SaaS code. It provides key information about an error,
including: the `reason` as a human-readable string, `details` as a dictionary that can be used to attach arbitrary,
more technical information to provide the context in which this error happened, and an `id` which is automatically
generated. The id allows referencing specific exception occurrences in logs which can help with debugging. The 
class is defined as follows:
```shell
class SaaSException(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._reason = reason
        self._details = details
        self._id = helpers.generate_random_string(16)

    @property
    def reason(self):
        return self._reason

    @property
    def details(self):
        return self._details

    @property
    def id(self):
        return self._id
```


### Exception Hierarchy
`SaaSException` is the base class for all exception types defined in the SaaS Middleware. Most of the following 
exception types are highly specific and occur in a single place only. Noteworthy exception types are described in more
details.

- `CLIException` is the baseclass for exceptions originating in the CLI subsystem.
  - `CLIRuntimeError`  is used for all errors that happen during execution of CLI commands. It is very commonly used in
  the CLI subsystem. Whenever a CLI command cannot be further executed, a`CLIRuntimeError` is raised. Other exceptions
    (including `SaaSException` types) may be caught and translated into `CLIRuntimeError` exceptions. The SaaS CLI
    subsystem catches all `SaaSException` types and prints the reason on `stdout` (see `main` in `saas_cli.py`). Since
    it can't be ruled that there are exceptions that have not been translated into `CLIRuntimeError`, there is a 
    general catch block for `Exception` types in `saas_cli.py`.
    
- `CryptographyException` is the baseclass for exceptions originating in the `cryptography` subsystem.
  - `NoPrivateKeyFoundError` 

- `KeystoreException` is the baseclass for exceptions originating in the `keystore` subsystem. There are currently
  no specific exception types defined and used in the `keystore` subsystem.  

- `NodeDBException` is the baseclass for exceptions originating in the `nodeb` subsystem. 
  - `DataObjectNotFoundError`
  - `InvalidIdentityError`
  - `UnexpectedIdentityError`

- `DORException` is the baseclass for exceptions originating in the `dor` subsystem. 
  - `DataObjectNotFoundError`  
  - `DataObjectContentNotFoundError`  
  - `IdentityNotFoundError`  
  - `ProcessorDescriptorNotFoundError`  
  - `InvalidProcessorDescriptorError`  
  - `InvalidGPPDataObjectError`  
  - `CloneRepositoryError`  
  - `CheckoutCommitError`  
  - `FetchDataObjectFailedError`

- `RTIException` is the baseclass for exceptions originating in the `dor` subsystem. 
  - `UnexpectedGPPMetaInformation`
  - `ProcessorNotDeployedError`
  - `JobDescriptorNotFoundError`
  - `JobStatusNotFoundError`
  - `GPPDataObjectNotFound`
  - `ProcessorNotAcceptingJobsError`
  - `UnresolvedInputDataObjectsError`
  - `MissingUserSignatureError`
  - `AdapterRuntimeError`
  - `MismatchingDataTypeOrFormatError`
  - `InvalidJSONDataObjectError`
  - `SSHConnectionError`
  - `DataObjectContentNotFoundError`
  - `DataObjectOwnerNotFoundError`
  - `DockerRuntimeError`
  - `BuildDockerImageError`

- `RESTException` is the baseclass for exceptions originating in the `rest` subsystem.
  - `UnexpectedHTTPError`  
  - `MalformedRequestError`  
  - `MalformedResponseError`  
  - `UnsuccessfulRequestError`  
  - `AuthorisationFailedError`  
  - `UnexpectedContentType`  
  - `MissingResponseSchemaError`  
  - `UnsuccessfulConnectionError`  

- `P2PException` is the baseclass for exceptions originating in the `p2p` subsystem.  
  - `ReceiveDataError`
  - `SendDataError`
  - `MalformedPreambleError`
  - `MismatchingBytesWrittenError`
  - `ResourceNotFoundError`
  - `DecodingJSONError`
  - `EncodingJSONError`
  - `HandshakeFailedError`
  - `MalformedMessageError`
  - `UnexpectedMessageTypeError`
  - `UnsupportedProtocolError`
  - `MismatchingRequestIdError`
  - `PeerUnavailableError`
  - `AttachmentNotFoundError`


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
