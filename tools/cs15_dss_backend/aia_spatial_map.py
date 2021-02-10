import os
import logging
import h5py
import numpy as np
import tools.cs15_dss_backend.aia_common as aia

from jsonschema import validate
from saas.utilities.general_helpers import load_json_from_file


logger = logging.getLogger('aia_processor_spatial_map')

descriptor = {
    'name': 'AIASpatialMap',
    'version': '0.1.0',
    'type': 'script',
    'input': [
        {
            'name': 'exposure_map',
            'data_type': 'RegularRasterDataObject',
            'data_format': 'hdf5'
        },
        {
            'name': 'climate_data',
            'data_type': 'RegularRasterDataObject',
            'data_format': 'hdf5'
        },
        {
            'name': 'parameters',
            'data_type': 'JSONObject',
            'data_format': 'json'
        }
    ],
    'output': [
        {
            'name': 'spatial_map',
            'data_type': 'RegularRasterDataObject',
            'data_format': 'hdf5'
        }
    ]
}

parameters_schema = {
    'type': 'object',
    'properties': {
        'damage_function': aia.damage_function_parameter_schema,
        'exposure_weights': aia.exposure_weights_parameter_schema
    },
    'required': ['exposure_weights']
}


def function(task_descriptor, working_directory, status_logger):
    """
    Processes input data and input parameters to calculate a 'spatial map' as defined by the CS 1.5 DSS framework.
    :param task_descriptor:
    :param working_directory:
    :param status_logger:
    :return:
    """
    logger.info(f"f({task_descriptor}, '{working_directory}')")

    try:
        # step 1: check parameters
        parameters_path = os.path.join(working_directory, "parameters")
        parameters = load_json_from_file(parameters_path)
        logger.info(f"parameters={parameters}")
        logger.info(f"parameters_schema={parameters_schema}")
        validate(instance=parameters, schema=parameters_schema)

        # step 2: load the exposure map
        exposure_map_path = os.path.join(working_directory, 'exposure_map')
        exposure_map_file = h5py.File(exposure_map_path, 'r')
        exposure_map = exposure_map_file['exposure_map']

        # step 2: determine spatial weights map
        temp = parameters['exposure_weights']
        exposure_weights = {}
        for item in temp:
            exposure_weights[item['mask_id']] = item['weight']
        spatial_weights_map = aia.determine_weights_map(exposure_map, exposure_weights)

        # step 3: determine damage function
        d_function = None
        if 'damage_function' in parameters:
            d_function = aia.create_damage_function(parameters['damage_function'])

        # step 4: generate spatial map for given climate data
        climate_data_path = os.path.join(working_directory, "climate_data")
        climate_data_file = h5py.File(climate_data_path, 'r')
        climate_data = climate_data_file['climate_data']

        # check if the shape match the exposure map
        if climate_data[0].shape != spatial_weights_map.shape:
            raise Exception(f'mismatching shapes: climate_data.shape={climate_data.shape} '
                            f'spatial_weights_map.shape={spatial_weights_map.shape}')

        climate_variable = climate_data.attrs['climate_variable']
        spatial_map = np.zeros(shape=climate_data.shape, dtype=np.float)
        for t in range(0, 24):
            # get the Z values at time t
            spatial_map[t] = np.array(climate_data[t], copy=True)

            # apply damage function if z_cat is 'pet'
            if d_function and climate_variable == 'pet':
                spatial_map[t] = d_function.apply(spatial_map[t])

            # apply exposure weights
            spatial_map[t] *= spatial_weights_map

        # create output file
        output_path = os.path.join(working_directory, 'spatial_map')
        f = h5py.File(output_path, "w")
        dset = f.create_dataset("spatial_map", data=spatial_map)
        dset.attrs['dimensions'] = climate_data.attrs['dimensions']
        dset.attrs['description'] = "CS1.5 DSS-demo Spatial Map"
        dset.attrs['climate_variable'] = climate_variable
        dset.attrs['weather_type'] = climate_data.attrs['weather_type']
        dset.attrs['unit'] = climate_data.attrs['unit']
        f.close()

        return True

    except Exception as e:
        logger.error(f"exception in function: {e}")
        return False
