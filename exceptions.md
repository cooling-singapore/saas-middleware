# Exceptions Guidelines
 
## Error handling
The SaaS Middleware supports different interfaces/entrypoints, HTTP and CLI.  
The main SaaS code (usually found in `service.py` files) SHOULD only be concerned about business logic and throw any errors as Exceptions instead of handling it on its own to simplify and allow for flexiblity in error handling in the main SaaS code. This shifts the responsibility of handling errors to the entrypoints, so that the they can decide on the appropriate response, such as returning an appropriate error message or returning an appropriate null value.

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

## Exception Hierarchy
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
