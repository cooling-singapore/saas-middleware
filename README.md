# Simulation-as-a-Service (SaaS) Middleware

The SaaS Middleware provides the necessary infrastructure to facilitate deployment and operations
of a loosely-coupled federation of models.

## Install
### Prerequisites
- Python 3.9 _(does not work on 3.10 as of now)_

Clone this repository and install it using pip:
```shell
git clone https://github.com/cooling-singapore/saas-middleware
pip install saas-middleware
```

## Usage
The SaaS Middleware can be used via a Command Line Interface (CLI) with this command once it is installed:
```shell
saas-cli
```

The CLI can be used in a 
non-interactive manner by providing corresponding command line parameters. In addition, some
commands also allow interactive use of the CLI in which case the user is prompted for input. 
The following sections explains how to use of the CLI for common use-cases.

### Create Identity
*If you are using the SaaS Middleware for the first time, you need to create an identity.*

Identities are used across the SaaS system for 
authentication/authorisation purposes as well for managing ownership and access rights to
data objects. An identity is required to operate SaaS node instances or to interact with 
remote instances.

To create an identity, the user would have to provide a name for the identity, a contact (i.e. email) and a password.
In addition to a name and email, an identity is also associated with a set of keys for signing and encryption purposes,
which are generated upon creation of the identity. The identity would then be assigned a unique ID and be stored
together with the set of keys in the form of a JSON file called a keystore. The keystore can be referenced by the identity ID.

By default, the keystore will be created in the folder named `.keystore` in the home directory
(e.g. `$HOME\.keystore`), and can be changed by providing the `--keystore` flag.

Identities can be created interactively by following the prompts using:
```shell
saas-cli identity create

? Enter name:  foo bar
? Enter email:  foo.bar@email.com
? Enter password:  ****
? Re-enter password:  ****
New keystore created!
- Identity: foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
- Signing Key: EC/secp384r1/384/2623ce0ae4e4ebcc38c3e3f91bfb97f21300ea81a1f7f7fbe81796c25f68a94a
- Encryption Key: RSA/4096/9cdfc30cd996eb36e31a8e0ed39f08ccac600bba92c91b22d9a09028aef5f2a2
```
The example above shows the identity created with ID `bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv`.

Identities can also be created non-interactively by specifying the password as well as details
about the identity using command line parameters:
```shell
saas-cli --keystore=$KEYSTORE_PATH --password 'password' identity create --name 'foo bar' --email 'foo.bar@email.com'
```

After creating identities, the user can list all the keystores found in the keystore path using:
```shell
saas-cli identity list

Found 1 keystores in '/home/foo.bar/.keystore':
NAME     EMAIL              KEYSTORE/IDENTITY ID
----     -----              --------------------
foo bar  foo.bar@email.com  bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
```

The `--keystore` flag can be provided to the command above if it is not found in the default path.

#### Credentials
The keystore can also be used to store and associate credentials with the identity. 
These credentials can be used for deploying processors and running jobs.
For example, GitHub for cloning from private repositories or SSH for executing remote commands.
More information about deploying processors and running jobs can be found in the sections below.

Credentials can be added by following the prompts using:
```shell
saas-cli identity credentials add
```

For a list of all commands concerning identities, use:
```shell
saas-cli identity --help
```

### Running a SaaS Node Instance
A SaaS Node instance provides services to store data objects and to execute processors.
These services are provided by the Data Object Repository (DOR) and Runtime Infrastructure (RTI)
modules, respectively. Depending on the requirements, nodes can be configured to act as storage-only nodes
(by only starting the DOR service), execution-only nodes (by only starting the RTI service), or as full 
nodes (by starting DOR and RTI services). 

When starting a node, the user has to specify the datastore path where a node stores all its data,
and the ID of a keystore whose identity the node will use. By default, the datastore path will be in the home directory (e.g. `$HOME/.datastore`) and the keystore path to search for the ID in the home directory as well (e.g `$HOME/.keystore`). 

The user also has to assign the address and port for the REST and P2P service for the node. These addresses are used for nodes in the network to commmunicate with each other. Make sure that the ports being assigned are open and not used by other processes. Additionally, new nodes will need to connect to a boot node in the network to retrieve information about other nodes in the network. The boot node will be referenced by its P2P address and can be any node in the network. If the node that is the first node in the network, it can connect to itself. 

Lastly, there is an option to retain job history (job information are not stored by default) for debugging purposes.

```shell
saas-cli service

? Enter path to datastore:  /home/foo.bar/.datastore
? Enter address for REST service:  127.0.0.1:5001
? Enter address for P2P service:  127.0.0.1:4001
? Enter address for boot node:  127.0.0.1:4001
? Select the type of service:  Full node (i.e., DOR + RTI services)
? Retain RTI job history?  No
? Select the keystore:  foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
? Enter password:  ****

Storage directory (datastore) created at '/home/foo.bar/.datastore'.
Created 'full' node instance at 127.0.0.1:5001/127.0.0.1:4001 (keep RTI job history: No)
? Terminate the server?  (y/N)
```
The example above shows a node running with a REST service at address `127.0.0.1:5001`. This address will be used to interact with this node using the CLI. 


To do this non-interactively, the `--keystore-id` and `--password` parameters can be used in addition to the 
`--keystore` to provide information about which identity to use and where to find it.
The `--type` parameters can be used to indicate the configuration of the node as above. If the id or the password of the keystore are not indicated, they will have to be entered by 
the user interactively.

Example: 
```shell
saas-cli --keystore $HOME/Desktop/keystores --keystore-id '<put_id_here>' --password '<put_password_here>' service --type 'full' 
```

Other parameters can be used to specify the addresses for P2P and REST API services as well as a
boot node. For more options, use:
```shell
saas-cli service --help
```

### Adding and Removing a Data Object
One of the two core modules of a SaaS Node is the Data Object Repository (DOR). It stores data
objects and makes them available across the domain for jobs that are executed by a Runtime 
Infrastructure (RTI). The content of a data object can be virtually anything so as long as it
comes as a file.

When adding a new data object to a DOR, the user needs to specify the data type and format of
the data object. In addition, the user may use optional flags to indicate if access to the data 
object should be restricted (`--restrict-access`) and if the data object content should be 
encrypted (`--encrypt-content`). If access is restricted, the owner needs to explicitly grant
permission to other identities before they can make use of the data objects. If encryption is 
used, the CLI will use keystore functionality to create a content key and encrypt the data 
object before uploading it to the DOR. 

Example:
```shell
saas-cli dor --address 127.0.0.1:5001 add --restrict-access --encrypt-content --data-type 'JSONObject' --data-format 'json' $HOME/Desktop/data_object_a.json

? Select the keystore:  foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
? Enter password:  ****
Content key for object 53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098 added to keystore.
Data object added: {
    "access": [
        "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv"
    ],
    "access_restricted": true,
    "c_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "content_encrypted": true,
    "created_by": "foo bar",
    "created_t": 1644154698149,
    "data_format": "json",
    "data_type": "JSONObject",
    "obj_id": "53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098",
    "owner_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv",
    "tags": []
}
```
The example above shows the new data object `53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098` with an owner ID `bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv` which belongs to the identity used to add the data object.


If a data object consists of multiple files, the CLI will archive (e.g., using tar.gz) them and 
use the archive as data object content. Example: 
```shell
saas-cli dor --address 127.0.0.1:5001 add --restrict-access  --encrypt-content --data-type 'AB-JSONObject' $HOME/Desktop/data_object_a.json $HOME/Desktop/data_object_b.json
``` 

Data objects can only be removed by their owner. Example:
```shell
saas-cli dor --address 127.0.0.1:5001 remove 53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098  
```

If the data object `53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098` would not be
owned by the identity used to run the CLI, the request to delete the data object would be denied
by the DOR.

### Granting and Revoking Access to Data Objects 
If the access to a data object is restricted (see previous section), then only identities that
have been explicitly granted permission may use the data object. To grant access:
```shell
saas-cli dor --address 127.0.0.1:5001 access grant '<put-obj-here>' --iid '<put-identity-id-here>'  
```

When used interactively, the CLI will provide a list of all data objects owned by the user
as well as a list of all identities known the node:
```shell
saas-cli dor --address 127.0.0.1:5001 access grant

? Select the keystore:  foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
? Enter password:  ****
? Select data objects:  [53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098 [JSONObject/json] ['name=data_object_a.json']]
? Select the identity who should be granted access:  fu baz/fu.baz@email.com/1mwbctiw880pa05mcx8yo7ntofmum7ey2r9rkl9hu4g48
Granting access to data object 53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098 for identity 1mwbctiw880pa05mcx8yo7ntofmum7ey2r9rkl9hu4g48aw1bmve46p3la21gkzo...Done
```
The example above shows data object `53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098` granted access to owner `1mwbctiw880pa05mcx8yo7ntofmum7ey2r9rkl9hu4g48aw1bmve46p3la21gkzo`.

The user can then select the appropriate data object and identity to whom access should be 
granted. Similarly, when revoking access interactively, a list of data objects is provided
by the CLI:
```shell
saas-cli dor --address 127.0.0.1:5001 access revoke '<put-identity-id-here>' --obj-id '<put-obj-here>'
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
the descriptor of the processor. For an example of a repository, refer to the test processor [here](https://github.com/cooling-singapore/saas-processor-template).

A processor descriptor specifies the name, input/output interfaces and the configurations that it can run in. It is structured as follows:
```json
{
  "name": ...,
  "input": [
    ...
  ],
  "output": [
    ...
  ],
  "configurations": [
    ...
  ]
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
processor descriptor for the test processor looks as follows:
```json
{
  "name": "test-proc",
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
  ],
  "configurations": [
    "default", 
    "nscc"
  ]
}
```

Before a processor can be deployed, a Git Processor Pointer (GPP) in form of a data object 
needs to be added to a DOR in the same domain where the RTI can find it. Corresponding DOR 
functionality can be used for this purpose. 

Example:
```shell
saas-cli dor --address 127.0.0.1:5001 add-gpp --url 'https://github.com/cooling-singapore/saas-processor-template' --commit-id '7a87928' --path 'processor_test'

? Select the keystore:  foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
? Enter password:  ****
? Analyse repository at https://github.com/cooling-singapore/saas-processor-template to help with missing arguments?  Yes
Cloning repository 'saas-processor-template' to '/home/foo.bar/.temp/saas-processor-template'...Done
Checkout commit id 7a87928...Done
Load processor descriptor at 'processor_test'...Done
? Select the configuration profile:  default
GPP Data object added: {
    "access": [
        "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv"
    ],
    "access_restricted": false,
    "c_hash": "bd45cc8eef34e8b59084c2192308ce4f96ef077d7d541e7d4ca690cc9674fac2",
    "content_encrypted": false,
    "created_by": "foo bar",
    "created_t": 1644154974976,
    "data_format": "json",
    "data_type": "Git-Processor-Pointer",
    "gpp": {
        "commit_id": "7a87928",
        "proc_config": "default",
        "proc_descriptor": {
            "configurations": [
                "default",
                "nscc"
            ],
            "input": [
                ...
            ],
            "name": "test-proc",
            "output": [
                ...
            ]
        },
        "proc_path": "processor_test",
        "source": "https://github.com/cooling-singapore/saas-processor-template"
    },
    "obj_id": "4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184",
    "owner_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv",
    "tags": []
}
```
The example above shows that the GPP data object is stored in the DOR with an object ID of `4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184` and a processor name of `test-proc`.

The `--url` parameters is used to point at the repository while the `--path` parameters specifies
where to find the `processor.py` and the `descriptor.json` files. In addition, `--commit-id` can 
be used to specify the exact commit that should be used for deployment. This allows, deployment
of previous versions of the processor. 

Once the GPP data object is available in a DOR, the RTI can be instructed to deploy the 
processor on the node. Deployment requires to indicate the ID of the processor which is equal
to the object ID of the GPP data object. 

Example:
```shell
saas-cli rti --address 127.0.0.1:5001 deploy '4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184'
```

If a processor ID is not specified, the CLI will allow the user to interactively select the GPP
data object for deployment:
```shell
saas-cli rti --address 127.0.0.1:5001 deploy

? Select the keystore:  foo bar/foo.bar@email.com/bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv
? Enter password:  ****
? Select the processor you would like to deploy:  test-proc from https://github.com/cooling-singapore/saas-processor-template at processor_test
? Select the deployment type:  Native Deployment
? Use an SSH profile for deployment?  No
Deploying processor 4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184...Done
```

Note that the RTI will search for GPP data object across the entire domain if a processor ID is
specified. However, in interactive mode, the CLI will only search for GPP data objects on the 
same node as the RTI (specified using `--address`).

Undeployment works in the same fashion as deployment. If a processor id is not specified, the CLI 
will fetch a list of processors deployed on the node and let the user select:
```shell
saas-cli rti --address 127.0.0.1:5001 undeploy

? Select the processor(s) you would like to undeploy:  [test-proc/4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184]
Undeploy processor 4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184...Done
```

### Submit Job and Check Status
Once a processor is deployed, it can be used to perform computational jobs. When submitting
a job to an RTI, the id of the processor needs to be specified. For all items in the 
processor's input interface, a corresponding data object needs to be provided either
by-reference (i.e., using the id of a data object stored in a DOR) or by-value (i.e., by 
directly providing the value for the input item as `json` object). For all items in the 
processor's output interface, a job needs to specify the future owner of the data object once
it has been produced, whether it should have restricted access and whether it should be 
encrypted. 

All these information has to be written in a job descriptor in the form of a JSON file. 

Example:
```json
{
  "processor_id": "4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184",
  "input": [
    {
      "name": "a",
      "type": "reference",
      "obj_id": "53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098"
    },
    {
      "name": "b",
      "type": "value",
      "value": {
        "v": 2
      }
    }
  ],
  "output": [
    {
      "name": "c",
      "owner_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv",
      "restricted_access": false,
      "content_encrypted": false
    }
  ],
  "user_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv"
}

```

A job can be submitted using a job descriptor file as above using:
```shell
saas-cli rti --address 127.0.0.1:5001 submit --job $HOME/Desktop/job_descriptor.json

Job submitted: job-id=TUAzUGI8
```

If the job has been successfully submitted, a job id will be returned. This id can be used
to check on the status of the job:
```shell
saas-cli rti --address 127.0.0.1:5001 status TUAzUGI8

Job descriptor: {
    "id": "TUAzUGI8",
    "proc_id": "4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184",
    "retain": false,
    "task": {
        "input": [
            {
                "name": "a",
                "type": "reference",
                "obj_id": "53348424fa87736ef6be3c2cd9dbd92d4d6b163ea7cc7fb9cee1134e4000b098"
            },
            {
                "name": "b",
                "type": "value",
                "value": {
                    "v": 2
                }
            }
        ],
        "output": [
            {
                "content_encrypted": false,
                "name": "c",
                "owner_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv",
                "restricted_access": false,
                "target_node_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv"
            }
        ],
        "processor_id": "4a96a57539ed211711686262ca443e29ebdd9a24f55a37f1a1795d3088a24184",
        "user_iid": "bfckflp9zeezvqocolcu7f1g9grg20zw8mv5x8p7j9l7b0e4mahfqk9krwnc4wzv"
    }
}
Status: {
    "output": [
        {
            "name": "c",
            "obj_id": "8b41e90cf9a22f5b25b8f7f3eac6102b20f0e5beaacd9bb41be6696b99af9619"
        }
    ],
    "process_output:c": "done",
    "progress": "100",
    "state": "successful"
}
```
The example above shows the job `TUAzUGI8` is successful and output a data object `8b41e90cf9a22f5b25b8f7f3eac6102b20f0e5beaacd9bb41be6696b99af9619`.
