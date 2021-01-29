import os
import logging
import h5py
import numpy as np
import tools.cs15_dss_backend.aia_common as aia

from jsonschema import validate
from saas.utilities.general_helpers import load_json_from_file


logger = logging.getLogger('aia_processor_mean_variance_score')

descriptor = {
    'name': 'AIAMeanVarianceScore',
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
            'name': 'mean_variance_score',
            'data_type': 'MeanVarianceScoreDataObject',
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
    logger.info(f"f({task_descriptor}, '{working_directory}')")

    try:
        # step 1: check parameters
        parameters_path = os.path.join(working_directory, "parameters")
        parameters = load_json_from_file(parameters_path)
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
        spatial_weights_map = aia.determine_spatial_weights_map(exposure_map, exposure_weights)

        # step 3: determine damage function
        d_function = None
        if 'damage_function' in parameters:
            d_function = aia.create_damage_function(parameters['damage_function'])

        # step 4: generate mean variance score for given climate data
        climate_data_path = os.path.join(working_directory, f"climate_data")
        climate_data_file = h5py.File(climate_data_path, 'r')
        climate_data = climate_data_file['climate_data']

        # check if the shape match the exposure map
        if climate_data[0].shape != spatial_weights_map.shape:
            raise Exception(f'mismatching shapes: climate_data.shape={climate_data.shape} '
                            f'spatial_weights_map.shape={spatial_weights_map.shape}')

        climate_variable = climate_data.attrs['climate_variable']

        mean_variance_score = np.zeros((25, 6), dtype=np.float)
        # {
        #     'mean': [0 for t in range(24)],
        #     'var': [0 for t in range(24)],
        #     'min': [0 for t in range(24)],
        #     'max': [0 for t in range(24)],
        #     'upper_var': [0 for t in range(24)],
        #     'lower_var': [0 for t in range(24)]
        # }

        # for each hour (t=0...24) calculate the statistics
        z_values_day = None
        for t in range(0, 24):
            # get the Z values at time t
            z_values = np.array(climate_data[t])

            # apply damage function if z_cat is 'pet'
            if d_function and climate_variable == 'pet':
                z_values = d_function.apply(z_values)

            # np.savetxt("/Users/temp/Desktop/t{}_2_zvalues_after_dfunc.csv".format(t), z_values, delimiter=",")

            # apply exposure map
            z_values = z_values * spatial_weights_map

            # np.savetxt("/Users/temp/Desktop/t{}_3_zvalues_after_spatial_weights.csv".format(t), z_values, delimiter=",")

            # remove NaN values
            z_values = z_values[~np.isnan(z_values)]
            # np.savetxt("/Users/temp/Desktop/t{}_4_zvalues_after_nan_removal.csv".format(t), z_values, delimiter=",")

            # calculate mean and upper/lower semivariance
            mean = np.mean(z_values)
            upper_values = z_values[z_values >= mean]
            lower_values = z_values[z_values < mean]
            upper_values = upper_values - mean
            lower_values = lower_values - mean
            upper_var = np.inner(upper_values, upper_values) / z_values.size
            lower_var = np.inner(lower_values, lower_values) / z_values.size

            # assign to result data set
            mean_variance_score[t][0] = mean
            mean_variance_score[t][1] = np.var(z_values)
            mean_variance_score[t][2] = np.min(z_values)
            mean_variance_score[t][3] = np.max(z_values)
            mean_variance_score[t][4] = upper_var
            mean_variance_score[t][5] = lower_var

            # append the Z values to the data set for the whole day
            if z_values_day is None:
                z_values_day = z_values

            else:
                z_values_day = np.concatenate((z_values_day, z_values))

        # calculate mean and upper/lower semivariance (for the full day data)
        mean = np.mean(z_values_day)
        upper_values = z_values_day[z_values_day >= mean]
        lower_values = z_values_day[z_values_day < mean]
        upper_values = upper_values - mean
        lower_values = lower_values - mean
        upper_var = np.inner(upper_values, upper_values) / z_values_day.size
        lower_var = np.inner(lower_values, lower_values) / z_values_day.size

        # assign to result data set (i.e., a 25th value for each result category
        # with statistics for the entire 24h period).
        mean_variance_score[24][0] = mean
        mean_variance_score[24][1] = np.var(z_values_day)
        mean_variance_score[24][2] = np.min(z_values_day)
        mean_variance_score[24][3] = np.max(z_values_day)
        mean_variance_score[24][4] = upper_var
        mean_variance_score[24][5] = lower_var

        # create output file
        output_path = os.path.join(working_directory, 'mean_variance_score')
        f = h5py.File(output_path, "w")
        dset = f.create_dataset("mean_variance_score", data=mean_variance_score)
        dset.attrs['dimensions'] = ['time', 'mean variance score: mean, var, min, max, upper_var, lower_var']
        dset.attrs['description'] = "CS1.5 DSS-demo Spatial Map"
        dset.attrs['climate_variable'] = climate_variable
        dset.attrs['weather_type'] = climate_data.attrs['weather_type']
        dset.attrs['unit'] = climate_data.attrs['unit']
        f.close()

        return True

    except Exception as e:
        logger.error(f"exception in function: {e}")
        return False
