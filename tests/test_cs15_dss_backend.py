import unittest
import logging
import os
import time
import json
import requests


from tests.testing_environment import TestingEnvironment
from jsonschema import validate
from saas.utilities.general_helpers import get_timestamp_now, all_in_dict, dump_json_to_file
from saas.utilities.blueprint_helpers import create_authentication, create_authorisation

import tools.cs15_dss_backend.aia_common as aia
from tools.cs15_dss_backend.aia_spatial_map import descriptor as aia_sm_descriptor
from tools.cs15_dss_backend.aia_spatial_map import parameters_schema as aia_sm_parameters_schema
from tools.cs15_dss_backend.aia_spatial_map import function as f_spatial_map

from tools.cs15_dss_backend.aia_mean_variance_score import descriptor as aia_mvs_descriptor
from tools.cs15_dss_backend.aia_mean_variance_score import parameters_schema as aia_mvs_parameters_schema
from tools.cs15_dss_backend.aia_mean_variance_score import function as f_mean_variance_score

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)


def update_tags(dor_address, owner, sender, obj_id, tags):
    body = {
        'tags': []
    }

    # populate the tags array
    for key in tags:
        value = tags[key]

        body['tags'].append({
            'key': key,
            'value': value
        })

    url = f"http://{dor_address[0]}:{dor_address[1]}/repository/{obj_id}/tags"
    authentication = create_authentication(f"PUT:/repository/{obj_id}/tags", sender, body)
    authorisation = create_authorisation(f"PUT:/repository/{obj_id}/tags", owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content).json()
    return r['reply']


def get_tags(dor_address, sender, obj_id):
    url = f"http://{dor_address[0]}:{dor_address[1]}/repository/{obj_id}/tags"
    authentication = create_authentication(f"GET:/repository/{obj_id}/tags", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['tags']


def upload_data_object(dor_address, data_object_path, owner, data_type, data_format, sender, created_by='unknown'):
    url = f"http://{dor_address[0]}:{dor_address[1]}/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': data_type,
            'data_format': data_format,
            'created_t': get_timestamp_now(),
            'created_by': created_by
        }
    }

    authentication = create_authentication('POST:/repository', sender, body, data_object_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(data_object_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def add_aia_processor_data_object(dor_address, source_path, descriptor, sender, owner):
    url = f"http://{dor_address[0]}:{dor_address[1]}/repository"
    body = {
        'type': 'processor',
        'owner_public_key': owner.public_as_string(),
        'descriptor': descriptor
    }

    authentication = create_authentication('POST:/repository', sender, body, source_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(source_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def deploy_aia_processor(rti_address, sender, proc_id):
    url = f"http://{rti_address[0]}:{rti_address[1]}/processor/{proc_id}"
    authentication = create_authentication(f"POST:/processor/{proc_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_deployed(rti_address, sender):
    url = f"http://{rti_address[0]}:{rti_address[1]}/processor"
    authentication = create_authentication("GET:/processor", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['deployed'] if 'deployed' in r['reply'] else None


def submit_aia_job(rti_address, sender, owner, proc_id, exposure_map_id, climate_data_id, parameters):
    url = f"http://{rti_address[0]}:{rti_address[1]}/processor/{proc_id}/jobs"
    body = {
        'type': 'task',
        'descriptor': {
            'processor_id': proc_id,
            'input': [
                {
                    'name': 'exposure_map',
                    'type': 'reference',
                    'obj_id': exposure_map_id
                },
                {
                    'name': 'climate_data',
                    'type': 'reference',
                    'obj_id': climate_data_id
                },
                {
                    'name': 'parameters',
                    'type': 'value',
                    'value': parameters
                }
            ],
            'output': {
                'owner_public_key': owner.public_as_string()
            }
        }
    }

    authentication = create_authentication(f"POST:/processor/{proc_id}/jobs", sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['job_id'] if 'job_id' in r['reply'] else None


def get_jobs(rti_address, sender, proc_id):
    url = f"http://{rti_address[0]}:{rti_address[1]}/processor/{proc_id}/jobs"
    authentication = create_authentication(f"GET:/processor/{proc_id}/jobs", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['jobs'] if 'jobs' in r['reply'] else None


def get_job(rti_address, sender, proc_id, job_id):
    url = f"http://{rti_address[0]}:{rti_address[1]}/processor/{proc_id}/jobs/{job_id}"
    authentication = create_authentication(f"GET:/processor/{proc_id}/jobs/{job_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply'] if all_in_dict(['job_descriptor', 'status'], r['reply']) else None


def export_data_object_content(dor_address, sender, obj_id, owner, destination_path):
    url = f"http://{dor_address[0]}:{dor_address[1]}/repository/{obj_id}/content"
    authentication = create_authentication(f"GET:/repository/{obj_id}/content", sender)
    authorisation = create_authorisation(f"GET:/repository/{obj_id}/content", owner)
    content = {
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    with requests.get(url, data=content, stream=True) as r:
        if r.status_code == 401:
            return 401

        with open(destination_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

        return r.status_code



class CS15DSSBackendTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env.start_flask_app()

    @classmethod
    def tearDownClass(cls):
        env.stop_flask_app()

    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(3)

    def tearDown(self):
        pass

    def test_convert_and_upload(self):
        sender = self.keys[0]
        owner = self.keys[1]

        climate_data_source_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.csv"
        climate_data_destination_path = os.path.join(env.wd_path, 'pet_w0.hdf5')
        aia.convert_climate_data(climate_data_source_path, climate_data_destination_path, "pet", "w0")
        assert os.path.isfile(climate_data_destination_path)

        obj_id = upload_data_object(env.rest_api_address, climate_data_destination_path,
                                    owner, "RegularRasterDataObject", "hdf5", sender, 'heiko')
        logger.info(f"climate data object id: {obj_id}")
        assert obj_id

        update_tags(env.rest_api_address, owner, sender, obj_id, {
            'scenario': 'cbd_s51',
            'climatic_variable': 'pet',
            'weather_type': 'w0'
        })

        tags = get_tags(env.rest_api_address, sender, obj_id)
        logger.info(f"tags: {tags}")
        assert len(tags) == 3
        assert tags['scenario'] == 'cbd_s51'
        assert tags['climatic_variable'] == 'pet'
        assert tags['weather_type'] == 'w0'

        exposure_map_source_path = "/Users/heikoaydt/Desktop/attachment/exposure_map"
        exposure_map_destination_path = os.path.join(env.wd_path, 'exposure_map.hdf5')
        aia.convert_exposure_map(exposure_map_source_path, exposure_map_destination_path)
        assert os.path.isfile(exposure_map_destination_path)

        obj_id = upload_data_object(env.rest_api_address, exposure_map_destination_path, owner,
                                    "RegularRasterDataObject", "hdf5", sender, 'heiko')
        logger.info(f"exposure map data object id: {obj_id}")
        assert obj_id

        update_tags(env.rest_api_address, owner, sender, obj_id, {
            'scenario': 'cbd_s51'
        })

        tags = get_tags(env.rest_api_address, sender, obj_id)
        logger.info(f"tags: {tags}")
        assert len(tags) == 1
        assert tags['scenario'] == 'cbd_s51'

    def test_aia_proc_deployment(self):
        sender = self.keys[0]
        owner = self.keys[1]

        proc_id0 = add_aia_processor_data_object(env.rest_api_address,
                                                 '../tools/cs15_dss_backend/aia_spatial_map.py',
                                                 aia_sm_descriptor, sender, owner)
        assert proc_id0

        proc_id1 = add_aia_processor_data_object(env.rest_api_address,
                                                 '../tools/cs15_dss_backend/aia_mean_variance_score.py',
                                                 aia_mvs_descriptor, sender, owner)
        assert proc_id1

        deploy_aia_processor(env.rest_api_address, sender, proc_id0)
        deploy_aia_processor(env.rest_api_address, sender, proc_id1)

        deployed = get_deployed(env.rest_api_address, sender)
        assert len(deployed) == 3
        assert proc_id0 in deployed
        assert proc_id1 in deployed

    def test_execute_aia_spatial_map(self):
        climate_data_source_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.csv"
        climate_data_destination_path = os.path.join(env.wd_path, 'climate_data')
        aia.convert_climate_data(climate_data_source_path, climate_data_destination_path, "pet", "w0")
        assert os.path.isfile(climate_data_destination_path)

        exposure_map_source_path = "/Users/heikoaydt/Desktop/attachment/exposure_map"
        exposure_map_destination_path = os.path.join(env.wd_path, 'exposure_map')
        aia.convert_exposure_map(exposure_map_source_path, exposure_map_destination_path)
        assert os.path.isfile(exposure_map_destination_path)

        parameters = {
            'damage_function': {
                'name': 'range',
                'arguments': ['25.0', '28.5']
            },
            'exposure_weights': [
                {'mask_id': '1', 'weight': 0.6},
                {'mask_id': '2', 'weight': 0.8},
                {'mask_id': '3', 'weight': 1.0}
            ]
        }
        validate(instance=parameters, schema=aia_sm_parameters_schema)
        parameters_path = os.path.join(env.wd_path, 'parameters')
        dump_json_to_file(parameters, parameters_path)
        assert os.path.isfile(parameters_path)

        task_descriptor = {
            'type': 'task',
            'descriptor': {
                'processor_id': '0x000',
                'input': [
                    {
                        'name': 'exposure_map',
                        'type': 'reference',
                        'obj_id': '0x000'
                    },
                    {
                        'name': 'climate_data',
                        'type': 'reference',
                        'obj_id': '0x000'
                    },
                    {
                        'name': 'parameters',
                        'type': 'value',
                        'data_type': 'Parameters',
                        'data_format': 'json',
                        'value': parameters
                    }
                ],
                'output': {
                    'owner_public_key': self.keys[0].public_as_string()
                }
            }
        }

        result = f_spatial_map(task_descriptor, env.wd_path, None)
        assert result

    def test_execute_aia_mean_variance_score(self):
        climate_data_source_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.csv"
        climate_data_destination_path = os.path.join(env.wd_path, 'climate_data')
        aia.convert_climate_data(climate_data_source_path, climate_data_destination_path, "pet", "w0")
        assert os.path.isfile(climate_data_destination_path)

        exposure_map_source_path = "/Users/heikoaydt/Desktop/attachment/exposure_map"
        exposure_map_destination_path = os.path.join(env.wd_path, 'exposure_map')
        aia.convert_exposure_map(exposure_map_source_path, exposure_map_destination_path)
        assert os.path.isfile(exposure_map_destination_path)

        parameters = {
            'damage_function': {
                'name': 'range',
                'arguments': ['25.0', '28.5']
            },
            'exposure_weights': [
                {'mask_id': '1', 'weight': 0.6},
                {'mask_id': '2', 'weight': 0.8},
                {'mask_id': '3', 'weight': 1.0}
            ]
        }
        validate(instance=parameters, schema=aia_mvs_parameters_schema)
        parameters_path = os.path.join(env.wd_path, 'parameters')
        dump_json_to_file(parameters, parameters_path)
        assert os.path.isfile(parameters_path)

        task_descriptor = {
            'type': 'task',
            'descriptor': {
                'processor_id': '0x000',
                'input': [
                    {
                        'name': 'exposure_map',
                        'type': 'reference',
                        'obj_id': '0x000'
                    },
                    {
                        'name': 'climate_data',
                        'type': 'reference',
                        'obj_id': '0x000'
                    },
                    {
                        'name': 'parameters',
                        'type': 'value',
                        'data_type': 'Parameters',
                        'data_format': 'json',
                        'value': parameters
                    }
                ],
                'output': {
                    'owner_public_key': self.keys[0].public_as_string()
                }
            }
        }

        result = f_mean_variance_score(task_descriptor, env.wd_path, None)
        assert result

    def test_submit_aia_jobs(self):
        sender = self.keys[0]
        owner = self.keys[1]

        # upload data objects

        climate_data_source_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.csv"
        climate_data_destination_path = os.path.join(env.wd_path, 'pet_w0.hdf5')
        aia.convert_climate_data(climate_data_source_path, climate_data_destination_path, "pet", "w0")
        assert os.path.isfile(climate_data_destination_path)

        climate_data_obj_id = upload_data_object(env.rest_api_address, climate_data_destination_path, owner,
                                                 "RegularRasterDataObject", "hdf5", sender, 'heiko')
        logger.info(f"data object id: {climate_data_obj_id}")
        assert climate_data_obj_id

        exposure_map_source_path = "/Users/heikoaydt/Desktop/attachment/exposure_map"
        exposure_map_destination_path = os.path.join(env.wd_path, 'exposure_map.hdf5')
        aia.convert_exposure_map(exposure_map_source_path, exposure_map_destination_path)
        assert os.path.isfile(exposure_map_destination_path)

        exposure_map_obj_id = upload_data_object(env.rest_api_address, exposure_map_destination_path, owner,
                                                 "RegularRasterDataObject", "hdf5", sender, 'heiko')
        logger.info(f"data object id: {exposure_map_obj_id}")
        assert exposure_map_obj_id

        # upload processor objects

        proc_id_sm = add_aia_processor_data_object(env.rest_api_address,
                                                   '../tools/cs15_dss_backend/aia_spatial_map.py',
                                                   aia_sm_descriptor, sender, owner)
        assert proc_id_sm

        proc_id_mvs = add_aia_processor_data_object(env.rest_api_address,
                                                    '../tools/cs15_dss_backend/aia_mean_variance_score.py',
                                                    aia_mvs_descriptor, sender, owner)
        assert proc_id_mvs

        # deploy processors

        deploy_aia_processor(env.rest_api_address, sender, proc_id_sm)
        deploy_aia_processor(env.rest_api_address, sender, proc_id_mvs)

        deployed = get_deployed(env.rest_api_address, sender)
        assert len(deployed) == 3
        assert proc_id_sm in deployed
        assert proc_id_mvs in deployed

        # submit spatial map job

        parameters = {
            'damage_function': {
                'name': 'range',
                'arguments': ['25.0', '28.5']
            },
            'exposure_weights': [
                {'mask_id': '1', 'weight': 0.6},
                {'mask_id': '2', 'weight': 0.8},
                {'mask_id': '3', 'weight': 1.0}
            ]
        }
        validate(instance=parameters, schema=aia_sm_parameters_schema)

        job_id_sm = submit_aia_job(env.rest_api_address, sender, owner, proc_id_sm,
                                   exposure_map_obj_id, climate_data_obj_id, parameters)
        assert job_id_sm is not None

        jobs_sm = get_jobs(env.rest_api_address, self.keys[0], proc_id_sm)
        logger.info(f"jobs_sm={jobs_sm}")
        assert jobs_sm is not None
        assert len(jobs_sm) == 1

        # submit mean variance score job

        parameters = {
            'damage_function': {
                'name': 'range',
                'arguments': ['25.0', '28.5']
            },
            'exposure_weights': [
                {'mask_id': '1', 'weight': 0.6},
                {'mask_id': '2', 'weight': 0.8},
                {'mask_id': '3', 'weight': 1.0}
            ]
        }
        validate(instance=parameters, schema=aia_mvs_parameters_schema)

        job_id_mvs = submit_aia_job(env.rest_api_address, sender, owner, proc_id_mvs,
                                    exposure_map_obj_id, climate_data_obj_id, parameters)
        assert job_id_mvs is not None

        jobs_mvs = get_jobs(env.rest_api_address, self.keys[0], proc_id_mvs)
        logger.info(f"jobs_mvs={jobs_mvs}")
        assert jobs_mvs is not None
        assert len(jobs_mvs) == 1

        # wait until all jobs are done
        pending = [
            ['spatial map', proc_id_sm, job_id_sm, None],
            ['mean variance score', proc_id_mvs, job_id_mvs, None]
        ]
        done = []
        while pending:
            item = pending.pop(0)
            label = item[0]
            proc_id = item[1]
            job_id = item[2]

            job_info = get_job(env.rest_api_address, self.keys[0], proc_id, job_id)
            if not job_info:
                pending.append(item)

            else:
                status = job_info['status']
                logger.info(f"descriptor[{label}]={job_info['job_descriptor']}")
                logger.info(f"status[{label}]={status}")
                if 'status' in status:
                    item[3] = status['status']
                    if item[3] == 'running':
                        pending.append(item)
                    else:
                        done.append(item)

            time.sleep(1)

        assert done[0][3] == 'successful'
        assert done[1][3] == 'successful'

    def test_appserver_scenario_analysis(self):
        sender = self.keys[0]
        owner = self.keys[1]

        # what weather types and climate variable to use?
        wt_selection = ['w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6']
        climate_variable = 'pet'

        # upload climate data objects
        obj_id = {}
        for wt in wt_selection:
            climate_data_source_path = f"/Users/heikoaydt/Desktop/attachment/climate_data/pet_{wt}.csv"
            climate_data_destination_path = os.path.join(env.wd_path, 'pet_w0.hdf5')
            aia.convert_climate_data(climate_data_source_path, climate_data_destination_path, climate_variable, wt)
            assert os.path.isfile(climate_data_destination_path)

            obj_id[wt] = upload_data_object(env.rest_api_address, climate_data_destination_path, owner,
                                            "RegularRasterDataObject", "hdf5", sender, 'heiko')
            logger.info(f"obj_id[{wt}]: {obj_id[wt]}")
            assert obj_id[wt]

        # upload exposure map data object
        exposure_map_source_path = "/Users/heikoaydt/Desktop/attachment/exposure_map"
        exposure_map_destination_path = os.path.join(env.wd_path, 'exposure_map.hdf5')
        aia.convert_exposure_map(exposure_map_source_path, exposure_map_destination_path)
        assert os.path.isfile(exposure_map_destination_path)

        exposure_map_obj_id = upload_data_object(env.rest_api_address, exposure_map_destination_path, owner,
                                                 "RegularRasterDataObject", "hdf5", sender, 'heiko')
        logger.info(f"exposure_map_obj_id: {exposure_map_obj_id}")
        assert exposure_map_obj_id

        # upload processor object
        proc_id = add_aia_processor_data_object(env.rest_api_address,
                                                '../tools/cs15_dss_backend/aia_mean_variance_score.py',
                                                aia_mvs_descriptor, sender, owner)
        assert proc_id

        # deploy processor
        deploy_aia_processor(env.rest_api_address, sender, proc_id)

        deployed = get_deployed(env.rest_api_address, sender)
        assert proc_id in deployed

        # define parameters
        parameters = {
            'damage_function': {
                'name': 'range',
                'arguments': ['25.0', '28.5']
            },
            'exposure_weights': [
                {'mask_id': '1', 'weight': 0.6},
                {'mask_id': '2', 'weight': 0.8},
                {'mask_id': '3', 'weight': 1.0}
            ]
        }
        validate(instance=parameters, schema=aia_mvs_parameters_schema)

        # submit jobs
        # jobs = {}
        pending = []
        for wt in obj_id:
            job_id = submit_aia_job(env.rest_api_address, sender, owner, proc_id,
                                    exposure_map_obj_id, obj_id[wt], parameters)
            assert job_id is not None

            pending.append([f'mean variance score', wt, proc_id, job_id, None, None])

        # wait until all jobs are done
        done = []
        while pending:
            item = pending.pop(0)
            label = f"{item[0]}[{item[1]}]"
            proc_id = item[2]
            job_id = item[3]

            job_info = get_job(env.rest_api_address, self.keys[0], proc_id, job_id)
            if not job_info:
                pending.append(item)

            else:
                status = job_info['status']
                logger.info(f"descriptor[{label}]={job_info['job_descriptor']}")
                logger.info(f"status[{label}]={status}")
                if 'status' in status:
                    item[4] = status['status']
                    if item[4] == 'running':
                        pending.append(item)
                    else:
                        item[5] = status['output:mean_variance_score']
                        done.append(item)

            time.sleep(1)

        # fetch the mean variance score data objects
        for job in done:
            assert job[4] == 'successful'
            assert job[5]

            obj_id = job[5]
            destination_path = os.path.join(env.wd_path, f"mean_variance_score_{job[1]}")
            export_data_object_content(env.rest_api_address, sender, obj_id, owner, destination_path)
            assert os.path.exists(destination_path)


if __name__ == '__main__':
    unittest.main()
