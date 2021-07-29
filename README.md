# Simulation-as-a-Service (SaaS) Middleware

The SaaS Middleware provides the necessary infrastructure to facilitate deployment and operations
of a loosely-coupled federation of models.

## Install
Install the following dependencies:
```
pip3 install cryptography canonicaljson flask flask_cors requests jsonschema sqlalchemy docker
```

## Usage
The SaaS Middleware can be used via a Command Line Interface (CLI). The CLI can be used in a 
non-interactive manner by providing corresponding command line parameters. In addition, some
commands also allow interactive use of the CLI in which case the user is prompted for input. 
The following sections explains how to use of the CLI for common use-cases.

### Create Identity
If you are using the SaaS Middleware for the first time, you need to create an identity. In
addition to a name and contact (e.g., email), an identity is also associated with a set of
keys for signing and encryption purposes. Identities are used across the SaaS system for
authentication/authorisation purposes as well for managing ownership and access rights to
data objects. An identity is required to operate SaaS node instances or to interact with 
remote instances:
```shell
./saas_cli.py identity create
```

Identities can also be created non-interactively by specifying the password as well as details
about the identity using command line parameters:
```shell
./saas_cli.py --keystore=$HOME/Desktop/keystores --password 'password' identity create --name 'foo bar' --email 'foo.bar@email.com'
```

For a list of all commands concerning identities, use:
```shell
./saas_cli.py identity --help
```

### Update SMTP Information
Certain functionality of a SaaS Node requires the ability to send emails. There is no dedicated
SaaS email service (yet). Instead, SaaS Nodes use SMTP credentials of existing email accounts.
The keystore of the identity used by a node will have to provide these credentials. The CLI can
be used to update this information interactively:
```shell
./saas_cli.py identity smtp
```

To just display the details of a keystore/identity (including SMTP information):
```shell
./saas_cli.py --keystore=$HOME/Desktop/keystores identity info
```

Note that in the above examples only the keystore directory is set explicitly. If more than one
keystores are found in this directory, the user can select interactively. Of course, it is also
possible to indicate the keystore id (`--keystore-id`) and also the password (`--password`) if 
needed.

### Running a SaaS Node Instance
A SaaS Node instance provides services to store data objects and to execute processors. These
services are provided by the Data Object Repository (DOR) and Runtime Infrastructure (RTI)
modules, respectively. 

Node instances require an identity in order to run. The `--keystore-id` and `--password` 
parameters can be used in addition to the `--keystore` to provide information about which
identity to use and where to find it. Make sure the identity used for the node has valid
SMTP credentials set (see previous section).

Depending on the requirements, nodes can be configured to act as storage-only nodes (by only 
starting the DOR service), execution-only nodes (by only starting the RTI service), or as full 
nodes (by starting DOR and RTI services). The `--type` parameters can be used to indicate the 
configuration. Example: 
```shell
./saas_cli.py --keystore $HOME/Desktop/keystores --keystore-id '<put_id_here>' --password '<put_password_here>' service --type 'full' 
```
If the id or the password of the keystore are not indicated, they will have to be entered by 
the user interactively.

It is also possible to specify the datastore path where a node stores all its data. 
Unless explicitly specified, default values will be used. When starting a node
interactively, default values for keystore (`$HOME/.keystore`) and datastore (`$HOME/.datastore`)
locations will be used. If multiple identities are available, the user has to select one 
interactively during start up:
```shell
./saas_cli.py service
```

Other parameters can be used to specify the addresses for P2P and REST API services as well as a
boot node. For more options, use:
```shell
./saas_cli.py service --help
```

### Adding and Removing a Data Object
One of the two core modules of a SaaS Node is the Data Object Repository (DOR). It stores data
objects and makes them available across the domain for jobs that are executed by a Runtime 
Infrastructure (RTI). The content of a data object can be virtually anything so as long as it
comes as a file. If a data object consists of multiple files, the CLI will archive (e.g., using
tar gz) them and use the archive as data object content.

When adding a new data object to a DOR, the user needs to specify the data type and format of
the data object. In addition, the user may use optional flags to indicate if access to the data 
object should be restricted (`--restrict-access`) and if the data object content should be 
encrypted (`--encrypt-content`). If access is restricted, the owner needs to explicitly grant
permission to other identities before they can make use of the data objects. If encryption is 
used, the CLI will use keystore functionality to create a content key and encrypt the data 
object before uploading it to the DOR. Example:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 add --restrict-access  --encrypt-content --data-type 'JSONObject' --data-format 'json' $HOME/Desktop/data_object_a.json 
```

Data objects can only be removed by their owner. Example:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 remove 53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098  
```

If the data object `53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098` would not be
owned by the identity used to run the CLI, the request to delete the data object would be denied
by the DOR.

### Granting and Revoking Access to Data Objects
If the access to a data object is restricted (see previous section), then only identities that
have been explicitly granted permission may use the data object. To grant access:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 grant --obj-id '<put-obj-here>' --iid '<put-identity-id-here>'  
```

When used interactively, the CLI will provide a list of all data objects owned by the user
as well as a list of all identities known the node:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 grant  
```

The user can then select the appropriate data object and identity to whom access should be 
granted. Similarly, when revoking access interactively, a list of data objects is provided
by the CLI:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 revoke  
```

### Deploying and Undeploying Processors
The other core module of a SaaS Node is the Runtime Infrastructure (RTI). It executes 
computational jobs using processors that have previously been deployed on the node. Depending
on the processor, a job will use some input data (provided by a DOR in form of data objects
or parameters in form a json objects) and produce some output data (as data objects that will
be stored on a DOR). Exactly what input is consumed and what output is produced is specified 
by the descriptor of the processor. 

Processors (i.e., their code) are expected to be made available by means of a Git repository
(e.g., hosted on Github). Such a repository needs to provide two things: (1) a `processor.py` 
file which contains the processor implementation and (2) a `descriptor.json` file which contains
the descriptor of the processor. A processor descriptor specifies the name and input/output
interfaces of the processor. It is structured as follows:
```json
{
  "name": ...,
  "input": [ ... ],
  "output": [ ... ]
}
```
The input and output interfaces (`input` and `output`) are lists of items that specify the input 
data consumed and output data produced by the processor, respectively. An item has a name, a
data type and data format:
```json
{
  "name": ...,
  "data_type": ...,
  "data_format": ...
}
```
Both, input and output interface, can have an arbitrary number of items. For example, the
processor descriptor for the `dummy` test processor looks as follows:
```json
{
  "name": "dummy",
  "input": [
    {
      "name": "a",
      "data_type": "JSONObject",
      "data_format": "json"
    },
    {
      "name": "b",
      "data_type": "JSONObject",
      "data_format": "json"
    }
  ],
  "output": [
    {
      "name": "c",
      "data_type": "JSONObject",
      "data_format": "json"
    }
  ]
}
```

Before a processor can be deployed, a Git Processor Pointer (GPP) in form of a data object 
needs to be added to a DOR in the same domain where the RTI can find it. Corresponding DOR 
functionality can be used for this purpose. Example:
```shell
./saas_cli.py dor --address 127.0.0.1:5001 add-proc --url 'https://github.com/cooling-singapore/saas-processor-template' --commit-id '09d00d6' --path 'processor_dummy'
```

The `--url` parameters is used to point at the repository while the `--path` parameters specifies
where to find the `processor.py` and the `descriptor.json` files. In addition, `--commit-id` can 
be used to specify the exact commit that should be used for deployment. This allows, deployment
of previous versions of the processor.

Once the GPP data object is available in a DOR, the RTI can be instructed to deploy the 
processor on the node. Deployment requires to indicate the id of the processor which is equal
to the object id of the GPP data object. Example:
```shell
./saas_cli.py rti --address 127.0.0.1:5001 deploy --proc-id 'efb70ca985a2eba8d19c509ccac02eb9b372d12a7b46588d52a0d30977c4cc22'
```

If `--proc-id` is not specified, the CLI will allow the user to interactively select the GPP
data object for deployment:
```shell
./saas_cli.py rti --address 127.0.0.1:5001 deploy
```

Note that the RTI will search for GPP data object across the entire domain if `--proc-id` is
specified. However, in interactive mode, the CLI will only search for GPP data objects on the 
same node as the RTI (specified using `--address`).

Undeployment works in the same fashion as deployment. If `--proc-id` is not specified, the CLI 
will fetch a list of processors deployed on the node and let the user select:
```shell
./saas_cli.py rti --address 127.0.0.1:5001 undeploy
```

### Submit Job and Check Status
Once a processor is deployed, it can be used to perform computational jobs. When submitting
a job to an RTI, the id of the processor needs to be specified. For all items in the 
processor's input interface, a corresponding data object needs to be provided either
by-reference (i.e., using the id of a data object stored in a DOR) or by-value (i.e., by 
directly providing the value for the input item as `json` object). For all items in the 
processor's output interface, a job needs to specify the future owner of the data object once
it has been produced, whether it should have restricted access and whether it should be 
encrypted. Example (assuming the dummy test processor descriptor from above):
```shell
./saas_cli.py rti --address 127.0.0.1:5001 submit --proc_id <proc-id-here> 'a:<object-id>' 'b:<path-to-value-json>' 'c:<future-owner-id>:false:false' 
```

If the job has been successfully submitted, a job id will be returned. This id can be used
to check on the status of the job:
```shell
./saas_cli.py rti --address 127.0.0.1:5001 status --job_id <job-id-here>
```
