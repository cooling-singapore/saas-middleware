# Exceptions Guidelines
 
## Error handling in _application_ code
Exceptions SHOULD be thrown in ___application___ code when it encounters an error and then handled in ___client___ code. 

_Application_ code refers to code that contains SaaS middleware business logic. i.e the Node services modules, `service.py`.

_Client_, in this context, refers to code that runs _application_ code. e.g. the HTTP route functions in `blueprint.py`.

This allows shifting the responsibility of handling errors to the _client_ code, so that the _client_ can decide what is the appropriate response. Such as returning an appropriate error message or returning an appropriate null value. This is important as the SaaS Middleware, has multiple interfaces (HTTP and CLI) each with its own concerns. In other words, _application_ code SHOULD only be concerned about business logic and __notifying__ the error.


e.g.
```python
# Application code
class Application:
    def do_something(value: str) -> int:
        if value != "a": # Some kind of specific error
            raise ValueError("value is not a") # Raise exception here
        return 123


# Client code
app = Application()
value = "abc"

def client1():
    try:
        result = app.do_something(value)
    except ValueError as e: # Handle exception here
        logger.error(e) # Client wants to log
        result = 0 # Client wants 0 if error

def client2():
    try:
        result = app.do_something(value)
    except ValueError as e: # Handle exception here
        result = None # Client wants None if error
```

## Custom Exceptions
When throwing exceptions, exceptions SHOULD try to be as specific as possible and avoid using the "catchall" base `Exception` class.

It is RECOMMENDED to use custom exceptions instead of the python builtin exceptions, as they provide extra functionality such as storing custom variables or stacktrace to the exception instance.

Specific custom exceptions MUST be defined for errors found in each of the different logical subsystems of the _application_. e.g. `DORException`, `RTIException`.

Custom exceptions SHOULD come with a useful and easy to read message that describes the error so that a non-technical user could easily understand it.  
e.g. Instead of `'key' not found in 'dict' object`, try `Input JSON file is missing the property 'key'`.

### Base Exceptions
Any new custom exceptions defined in the _application_ code MUST inherit from custom base exceptions as defined in the _application_. Custom exception base classes defined in the _application_ are modelled similar to a subset of the REST HTTP error status codes listed below.

|Exception Base Class|Related response code|Description|
|-|-|-|
ApplicationValueException|400 BAD REQUEST|SHOULD be used when the _application_ receives an invalid argument in the function call. This to differentiate errors that are caused by initial inputs vs error that are caused in the logic of the _application_.
ResourceNotFoundException|404 NOT FOUND|SHOULD be used when the _application_ is trying to retrieve a resource from a collection (e.g. database, list, dict) which should exist but is unable to find it.
ApplicationException|500 INTERNAL SERVER ERROR|SHOULD be used when there is an error within the _application_ such as a function could not be completed (e.g. could not undeploy a processor).
