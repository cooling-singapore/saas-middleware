# Simulation-as-a-Service (SaaS) Middleware Developer Resources

## Logging Guidelines
The SaaS Middleware uses the default [logging facility of Python](https://docs.python.org/3/library/logging.html).

### Log Levels
Logging defines a number of default [logging levels](https://docs.python.org/3/library/logging.html#levels). Although 
it is possible to define custom logging levels, it is RECOMMENDED to use default logging levels only. If necessary, a 
TRACE logging level may be introduced to allow for more detailed output for debugging purposes.

Meaning and usage of logging levels:

- `CRITICAL` and `ERROR`:
MUST only be used for exceptions, i.e., in case the normal workflow cannot continue. The log entry SHOULD be made at
  the location where the exception is caught/handled, not where the exception is thrown/created. CRITICAL log level 
  is reserved for exceptions that cause the application to crash, i.e., for conditions that leave the application in 
  a state in which it cannot recover or continue to function and thus requiring a restart. Exceptions SHOULD come 
  with a stack trace and a unique id, both of which MUST be mentioned in the log message. However, stack traces 
  SHOULD NOT be logged. Instead, stack traces SHOULD be stored in a separate file with the filename reflecting the 
  reference id of the exception.

- `WARNING`:
SHOULD be used for conditions that may cause a modification, but not a complete disruption, of the normal workflow.
  Warnings SHOULD be used to highlight situations/conditions that are unexpected or pointing at a potential problem. 
  Unlike error/critical logs, warning logs MUST be made where they occur. 

- `INFO`:
SHOULD be used to provide useful and meaningful information, allowing a system administrator or technical user to 
  understand the progress of the normal workflow. In a production environment, this SHOULD be the default level.

- `DEBUG`:
MUST provide technical information at sufficient level of detail to allow developers understand the nature of problems
  and to support the debugging process. Any information that is too technical or detailed to be logged as info-level
  message, MUST be logged as debug message. In a development environment, this SHOULD be the default level.

- `NOTSET`:
Not used.


### Destination
It MUST be possible to write logs stdout and/or multiple file(s). Furthermore, it SHOULD be possible to filter (e.g., 
by module name) and redirect logs to different files. In order to avoid extremely large log files, log files MUST be
automatically rolled over once they have reached a certain size.


### Format
The formatting of logging messages SHOULD be human- and machine-readable. The following information MUST be 
contained by any log message:
- Human-readable Timestamp: timestamp (using UTC) formatted as `yyyy-mm-dd HH:MM:SS[.zzz]` whereby the millisecond 
  portion is optional.
- Machine-readable Timestamp: timestamp (seconds/milliseconds since beginning of epoch) formatted as `SSSS[.zzz]` 
  whereby the milliseconds portion is optional.
- Module name: the name of the module that created this message.
- Log level: the log level in capital letters, i.e., `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG`.
- Message: the message itself may be structured flexibly according to the needs by the module to increase 
  human/machine readability.

Example:
```
2021-09-09 07:27:37.244 1631698929.244 [cli] INFO This is a example message. All is good!
```
