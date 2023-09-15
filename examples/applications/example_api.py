import os
import time
from typing import Optional, List, Tuple
from pprint import pprint

from saas.core.helpers import write_json_to_file, read_json_from_file
from saas.core.keystore import Keystore
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.dor.proxy import DORProxy
from saas.dor.schemas import GPPDataObject, DataObject
from saas.nodedb.proxy import NodeDBProxy
from saas.nodedb.schemas import NodeInfo
from saas.rti.proxy import RTIProxy
from saas.rti.schemas import Task, Job, JobStatus

"""
API Example: this example shows how to use the REST API to build an application. Note: there should be no reason
for an application developer to work directly with the API. Instead the SDK should be used which wraps the API in
a convenient set of classes and functions. 
"""


def create_and_publish_identity(node_address: Tuple[str, int], keystore_path: str, password: str) -> Keystore:
    # create a new keystore
    keystore = Keystore.create(keystore_path, 'John Doe', 'john.doe@somewhere.com', password)

    # at this point the keystore is already stored to disk (have a look and open it in a text editor).
    # the file is in json format and provides some public and private information. the private information
    # is encrypted. btw, the name of the keystore file reflects the Id of the identity and looks something
    # like this:
    identity = keystore.identity
    print(f"my identity id: {identity.id}")
    print(f"the keystore file is located at {keystore_path} and should look like this: {identity.id}.json")

    # nodes only accept working with identities which they are aware of. if you create a new identity you
    # need to publish it first before the nodes in your network will accept. btw, if your network consists
    # of multiple nodes, you can publish the identity to any node. it will propagate in the network on its
    # own. identity stuff is handled by the NodeDB component of a SaaS node, so we use the NodeDB proxy for
    # that.
    db = NodeDBProxy(node_address)

    # what identities does the node about?
    identities = db.get_identities()  # corresponding REST API call: curl 10.8.0.6:5001/api/v1/db/identity
    pprint(f"known identities: {identities}")

    # publish the identity...
    db.update_identity(identity)

    # ... and check again. you should see your identity now part of the result
    identities = db.get_identities()
    pprint(f"known identities: {identities}")

    return keystore


def upload_gpp_and_deploy_adapter(node_address: Tuple[str, int], user: Keystore) -> str:
    # check if the node supports RTI services. the NodeDB can be used to retrieve this information
    db = NodeDBProxy(node_address)
    node_info: NodeInfo = db.get_node()
    print(f"node info: {node_info}")
    if not node_info.rti_service:
        raise RuntimeError("Sorry this node doesn't support RTI services...")

    # check if the node uses strict deployment
    if node_info.strict_deployment:
        raise RuntimeError("Sorry this node uses strict deployment rules and cannot be used for this example app...")

    # all things data objects require to use a DOR service. let's check if the node supports it. btw, RTI and
    # DOR services do not have to be on the same node. you could have multiple nodes in your network supporting
    # both or only one or the other.
    if not node_info.dor_service:
        raise RuntimeError("Sorry this node doesn't support DOR services...")

    # set the parameters for the GPP...
    source = 'https://github.com/cooling-singapore/saas-processor-template'
    commit_id = '778bd126871d4759a1de4029872e52e97cc10be5'
    proc_path = 'processor_test'
    proc_config = 'default'
    owner = user.identity

    # we are using a test processor which is located in a public Github repository. if a private repository
    # is used then it is necessary to provide Github credentials that are valid for this repo. such credentials
    # could be stored in the user's keystore.
    github_credentials: Optional[GithubCredentials] = user.github_credentials.get(source)
    if github_credentials is not None:
        print(f"found Github credentials '{github_credentials.login}' for {source}.")
    else:
        print(f"no Github credentials found for {source}. let's hope the repo is public...")

    # upload a GPP data object that points to the example processor adapter.
    dor = DORProxy(node_address)
    meta: GPPDataObject = dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, owner,
                                                  github_credentials=github_credentials)
    print(f"this is the meta information of our GPP data object: {meta}")

    # let's get the object id... which in case of GPP data objects also correspond to the processor id used by the
    # RTI...
    obj_id = meta.obj_id
    proc_id = obj_id  # same same...

    # ok, now we can tell the RTI to deploy the processor. if the deployment of the processor is actually supposed
    # to take place on a remote machine (e.g., HPC cluster), then corresponding SSH credentials need to be provided
    # so the RTI can remotely login and install the processor there. similar to Github credentials, the SSH
    # credentials may be stored in the keystore.
    rti = RTIProxy(node_address)
    ssh_profile = 'some-name-used-to-identify-the-profile'
    ssh_credentials: Optional[SSHCredentials] = user.ssh_credentials.get(ssh_profile)
    if ssh_credentials is not None:
        print(f"found SSH credentials '{ssh_credentials.login}' for '{ssh_profile}'.")
    else:
        print(f"no SSH credentials found for '{ssh_profile}'. deploying locally...")
    rti.deploy(proc_id, user, github_credentials=github_credentials, ssh_credentials=ssh_credentials)

    # check what has been deployed
    deployed = rti.get_deployed()
    print(f"currently deployed: {deployed}")

    return proc_id


def submit_job(node_address: Tuple[str, int], proc_id: str, user: Keystore) -> Tuple[str, str]:
    # background: in this example, we use the example adapter found in '/examples/adapters' of the same repository
    # that contains this example application. the processor is simple: it takes two input data objects that
    # contain values, adds them up, and produces the sum as output. A + B = C

    # have a look at the descriptor.json of the adapter. we need to input data objects 'a' and 'b'. both have to be
    # in json format. when submitting a job you need to specify either (1) the id of the data object to be used for
    # this input OR (2) the value itself (only works for json). for this example, we will use both methods.

    # let's create a file with the contents for data object 'a'...
    a_path = os.path.join(os.environ['HOME'], 'a.json')
    a_content = {
        'v': 16
    }
    write_json_to_file(content=a_content, path=a_path)

    #  upload the content to the DOR and obtain the data object id for 'a'
    dor = DORProxy(node_address)
    owner = user.identity
    restricted = False  # we don't want to restrict access -> all users can access this data object
    encrypted = False  # the content of this data object is not encrypted

    # note that the following information must match *exactly* the specification of the input as defined in
    # 'descriptor.json'. basically, the adapter defines exactly what it accepts as input.
    data_type = 'JSONObject'
    data_format = 'json'

    # upload the data object content
    a_meta = dor.add_data_object(a_path, owner, restricted, encrypted, data_type, data_format)
    a_obj_id = a_meta.obj_id
    print(f"id for data object 'a': {a_obj_id}")

    # submitting a job requires a task descriptor which specifies the values/references for the input interface
    # of the processor adapter. this has to *exactly* match the specification of the processor adapter.

    # in case a data object is restricted, the user has to generate a valid signature to proof that the entity
    # submitting the job is indeed in possession of the private key for the user on whose behalf the data object
    # is accessed. in short: to proof the entity has the rights to use the data object. of course, this also
    # requires that the data object owner has actually given access permissions to the user...
    db = NodeDBProxy(node_address)
    rti_node_info = db.get_node()
    a_access_token = f"{rti_node_info.identity.id}:{a_obj_id}"
    a_signature = user.sign(a_access_token.encode('utf-8'))

    job_input = [
        Task.InputReference(
            name='a',
            type='reference',  # 'reference' because we have the content in a data object
            obj_id=a_obj_id,
            user_signature=a_signature  # not actually required because the data object is not restricted.
        ),
        Task.InputValue(
            name='b',
            type='value',  # 'value' because we provide the content directly
            value={
                'v': 2
            }
        )
    ]

    job_output = [
        Task.Output(
            name='c',
            owner_iid=user.identity.id,  # the same user will own product 'c'
            restricted_access=False,
            content_encrypted=False
        )
    ]

    # finally, submit the job
    rti = RTIProxy(node_address)
    job: Job = rti.submit_job(proc_id, job_input, job_output, user)
    print(f"this is the descriptor of the job we just submitted: {job}")

    return job.id, a_obj_id


def wait_for_job(node_address: Tuple[str, int], job_id: str, user: Keystore) -> None:
    rti = RTIProxy(node_address)
    while True:
        time.sleep(5)
        status: JobStatus = rti.get_job_status(job_id, with_authorisation_by=user)
        print(f"status={status}")

        if status.state == 'successful':
            break
        elif status.state == 'failed':
            raise RuntimeError("Ohoh... something went wrong with the job.")


def retrieve_results(node_address: Tuple[str, int], job_id: str, user: Keystore, download_path: str) -> str:
    # the resulting data object 'c' has been stored in the DOR. let's figure out the data object id
    rti = RTIProxy(node_address)
    status: JobStatus = rti.get_job_status(job_id, with_authorisation_by=user)
    c_meta = status.output['c']
    print(f"the object id of 'c' is: {c_meta.obj_id}")

    # get the content of data object 'c'
    dor = DORProxy(node_address)
    dor.get_content(c_meta.obj_id, with_authorisation_by=user, download_path=download_path)
    print(f"the content of data object 'c' is downloaded to '{download_path}'")

    return c_meta.obj_id


def retrieve_logs(node_address: Tuple[str, int], job_id: str, user: Keystore, download_path: str) -> None:
    # get the logs (if any) and store them
    rti = RTIProxy(node_address)
    rti.get_job_logs(job_id, user, download_path)
    print(f"the content of data object 'c' is downloaded to '{download_path}'")


def tag_data_object(node_address: Tuple[str, int], obj_id: str, tags: List[DataObject.Tag], user: Keystore) -> None:
    dor = DORProxy(node_address)
    meta = dor.update_tags(obj_id, user, tags)
    print(f"data object '{obj_id}' is now tagged which is reflected in the meta information: {meta}")


def search(node_address: Tuple[str, int], patterns: List[str]) -> List[DataObject]:
    dor = DORProxy(node_address)
    result: List[DataObject] = dor.search(patterns=patterns)
    return result


def clean_up(node_address: Tuple[str, int], proc_id: str, obj_ids: List[str], user: Keystore) -> None:
    # undeploy the processor
    rti = RTIProxy(node_address)
    rti.undeploy(proc_id, user)

    # delete data objects
    dor = DORProxy(node_address)
    for obj_id in obj_ids:
        dor.delete_data_object(obj_id, with_authorisation_by=user)

    # also delete the GPP data object (remember obj_id == proc_id)
    dor.delete_data_object(proc_id, with_authorisation_by=user)


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
    address = (host, port)  # the REST API address of your node
    directory = os.environ['HOME']
    pwd = "you probably shouldn't hardcode this..."
    keystore = create_and_publish_identity(address, directory, pwd)

    # you can also, load existing keystores instead of creating new ones all the time...
    keystore_id = keystore.identity.id
    keystore = Keystore.load(os.path.join(directory, f"{keystore_id}.json"), pwd)

    """
    (2) Deploying a processor (NOTE: if the node uses strict deployment rules, this only works if the keystore is 
    the same that has been used to start the node). Before deploying a processor on a node's RTI, you need to upload a 
    corresponding Github-Processor-Pointer (GPP) data object which contains the necessary details where to find the 
    code of the processor's SaaS adapter. Note that only nodes that support RTI services can be used to deploy adapters.
    """
    proc_id = upload_gpp_and_deploy_adapter(address, keystore)
    print(f"id of the deployed processor: {proc_id}")

    """
    (3) Now that the processor is deployed, we can submit a job.
    """
    job_id, a_obj_id = submit_job(address, proc_id, keystore)

    """
    (4) If everything went well, we should have received a job id. Now we have to wait for the job to tbe finished. 
    """
    wait_for_job(address, job_id, keystore)

    """
    (5) Ok, the job is done. Let's retrieve the result -> data object 'c' that has been produced by the processor.
    """

    # note that the identity who wants to download the content of the data object needs to have access which
    # may have to be granted first by the owner. in this example, we have always used the same identity, so the
    # user accessing the contents also happens to be the owner so no problem here.
    download_path = os.path.join(os.environ['HOME'], 'c.json')
    c_obj_id = retrieve_results(address, job_id, keystore, download_path)

    # load the result
    c = read_json_from_file(download_path)
    pprint(c)

    """
    (6) In addition to downloading the results you can also download the execution logs in case you want to know
    more what happened during the job execution. This is particularly useful if something went wrong.
    """
    download_path = os.path.join(os.environ['HOME'], 'logs.tar.gz')
    retrieve_logs(address, job_id, keystore, download_path)

    """
    (7) Say you want to tag the resulting data object so it will be easier to find in the future.
    """

    # note that tags come in key:value fashion.
    tag_data_object(address, c_obj_id, [
        DataObject.Tag(key='description', value='this is my first output data object.'),
        DataObject.Tag(key='contact', value={
            'name': 'Foo Bar',
            'contact': 'foo.bar@internet.com'
        })
    ], keystore)

    # once tagged, you can also search for data objects by using tags. patterns are matched against keys and
    # values of tags. as long as a pattern is contained by at least one tag (key or value), the object is
    # included in the result set.
    result = search(address, ['hello world'])
    pprint(result)

    """
    (8) Once we are done, we can clean up. Undeploy the processor and delete data objects
    """
    clean_up(address, proc_id, [a_obj_id, c_obj_id], keystore)


if __name__ == '__main__':
    main()
