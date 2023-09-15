import os
from pprint import pprint

from saas.core.helpers import write_json_to_file, read_json_from_file
from saas.core.keystore import Keystore
from saas.dor.schemas import DataObject
from saas.sdk.base import connect

"""
SDK Example: this example shows how to use the SDK to build an application. The SaaS SDK defines a set of convenient
classes and functions that supports most use cases. Should a use case not be supported, it is always possible to 
use the REST API directly.
"""


def main():
    """
    (1) Identity creation and publication
    The first thing that is needed when working with a SaaS Node is an identity. This identity will be used
    when interacting with a SaaS node. Identities are used to take ownership of data objects and to authorise
    certain actions (e.g., delete data object). Technically speaking, the identities concept is based on
    asymmetric cryptography and more specifically, public/private key pairs. In the SaaS context, we distinguish
    between a 'Keystore' and an 'Identity'. The 'Keystore' contains the private (secret) parts of an identity.
    This includes private keys and other credentials (e.g., SSH or Github credentials) that may be required.
    The 'Identity' is the public facing part of an identity, including public keys and information about the
    identity such as name and email address. An 'Identity' objects is derived from a 'Keystore'. While Identity
    can be shared freely, Keystore contents need to be kept safe (which is why parts of it is encrypted and
    password protected).
    """
    # create and publish a new identity...
    host = '127.0.0.1'
    port = 5001
    address = [host, port]  # the REST API address of your node
    directory = os.environ['HOME']
    password = "you probably shouldn't hardcode this..."

    # create a new keystore
    keystore = Keystore.create(directory, 'John Doe', 'john.doe@somewhere.com', password)
    print(f"my identity id: {keystore.identity.id}")
    print(f"the keystore file is located at {directory} and should look like this: {keystore.identity.id}.json")

    # use the keystore to create a SaaS context (the identity is automatically published to the node)
    context = connect(address, keystore)

    """
    (2) Deploying a processor (NOTE: if the node uses strict deployment rules, this only works if the keystore is 
    the same that has been used to start the node). Before deploying a processor on a node's RTI, you need to upload a 
    corresponding Github-Processor-Pointer (GPP) data object which contains the necessary details where to find the 
    code of the processor's SaaS adapter. Note that only nodes that support RTI services can be used to deploy adapters.
    """
    # upload the GPP
    source = 'https://github.com/cooling-singapore/saas-processor-template'
    commit_id = '778bd126871d4759a1de4029872e52e97cc10be5'
    proc_path = 'processor_test'
    proc_config = 'default'
    gpp = context.upload_gpp(source, commit_id, proc_path, proc_config)
    print(f"object id of the GPP data object: {gpp.meta.obj_id}")

    # get an RTI node and deploy the processor
    rti = context.rti()
    proc = gpp.deploy(rti)
    print(f"id of the deployed processor: {proc.descriptor.proc_id}")

    """
    (3) Now that the processor is deployed, we can submit a job.
    """
    # background: in this example, we use the example adapter found in '/examples/adapters' of the same repository
    # that contains this example application. the processor is simple: it takes two input data objects that
    # contain values, adds them up, and produces the sum as output. A + B = C

    # have a look at the descriptor.json of the adapter. we need to input data objects 'a' and 'b'. both have to be
    # in json format. when submitting a job you need to specify either (1) the id of the data object to be used for
    # this input OR (2) the value itself (only works for json). for this example, we will use both methods.

    # let's create a file with the contents for data object 'a'...
    a_path = os.path.join(directory, 'a.json')
    a_content = {
        "v": 16
    }
    write_json_to_file(content=a_content, path=a_path)

    # upload the content to the DOR and obtain the data object id for 'a'
    access_restricted = False  # we don't want to restrict access -> all users can access this data object
    obj_a = context.upload_content(a_path, 'JSONObject', 'json', access_restricted)
    print(f"id for data object 'a': {obj_a.meta.obj_id}")

    # submitting a job requires a task descriptor which specifies the values/references for the input interface
    # of the processor adapter. this has to *exactly* match the specification of the processor adapter.

    # in case a data object is restricted, the user has to generate a valid signature to proof that the entity
    # submitting the job is indeed in possession of the private key for the user on whose behalf the data object
    # is accessed. in short: to proof the entity has the rights to use the data object. of course, this also
    # requires that the data object owner has actually given access permissions to the user... the high-level
    # SDK takes care of creating signatures.
    output = proc.submit_and_wait({
        'a': obj_a,  # in this case we assign the object we just uploaded, a so called by-reference assignment
        'b': {"v": 2}  # in this case we assign the content of the data object directly, a so called by-value assignment
    })

    """
    (4) Ok, the job is done. Let's retrieve the result -> data object 'c' that has been produced by the processor.
    """

    # note that the identity who wants to download the content of the data object needs to have access which
    # may have to be granted first by the owner. in this example, we have always used the same identity, so the
    # user accessing the contents also happens to be the owner so no problem here.
    obj_c = output['c']
    download_path = os.path.join(directory, 'c')
    obj_c.download(download_path)

    # load the result
    c = read_json_from_file(download_path)
    pprint(c)

    """
    (5) In addition to downloading the results you can also download the execution logs in case you want to know
    more what happened during the job execution. This is particularly useful if something went wrong.
    """
    # download_path = os.path.join(os.environ['HOME'], 'logs.tar.gz')
    # retrieve_logs(address, job_id, keystore, download_path)

    """
    (6) Say you want to tag the resulting data object so it will be easier to find in the future.
    """

    # note that tags come in key:value fashion.
    obj_c.update_tags([
        DataObject.Tag(key='description', value='this is my first output data object.'),
        DataObject.Tag(key='contact', value={
            'name': 'Foo Bar',
            'contact': 'foo.bar@internet.com'
        })
    ])

    # once tagged, you can also search for data objects by using tags. patterns are matched against keys and
    # values of tags. as long as a pattern is contained by at least one tag (key or value), the object is
    # included in the result set.
    results = context.find_data_objects(['Foo'])
    results = [result.meta.dict() for result in results]
    pprint(results)

    """
    (7) Once we are done, we can clean up. Undeploy the processor and delete data objects
    """
    proc.undeploy()
    obj_a.delete()
    obj_c.delete()


if __name__ == '__main__':
    main()
