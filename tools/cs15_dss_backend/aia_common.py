import csv
import h5py
import logging
import numpy as np

from jsonschema import validate

logger = logging.getLogger(__name__)

damage_function_parameter_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string', 'enum': ['identity', 'range', 'step']},
        'arguments': {
            'type': 'array',
            'items': {'type': 'string'}
        }
    },
    'required': ['name', 'arguments']
}

exposure_weights_parameter_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'mask_id': {'type': 'string'},
            'weight': {'type': 'number'}
        },
        'required': ['mask_id', 'weight']
    }
}


class DamageFunctionIdentity:
    def apply(self, values):
        return np.array(values, copy=True)


class DamageFunctionRange:
    def __init__(self, limit_lower, limit_upper):
        self.limit_lower = limit_lower
        self.limit_upper = limit_upper

    def apply(self, values):
        result = np.where((values < self.limit_lower) | (values >= self.limit_upper), 1, values)
        result = np.where((result >= self.limit_lower) & (result < self.limit_upper), 0, result)

        return result


class DamageFunctionStep:
    def __init__(self, limit_0, limit_1, limit_2, value_0, value_1, value_2, value_3):
        self.limit_0 = limit_0
        self.limit_1 = limit_1
        self.limit_2 = limit_2
        self.value_0 = value_0
        self.value_1 = value_1
        self.value_2 = value_2
        self.value_3 = value_3

    def apply(self, values):
        result = np.where((values < self.limit_0), self.value_0, values)
        result = np.where((result >= self.limit_0) & (result < self.limit_1), self.value_1, result)
        result = np.where((result >= self.limit_1) & (result < self.limit_2), self.value_2, result)
        result = np.where((result >= self.limit_2), self.value_3, result)

        return result


def create_damage_function(parameters):
    """
    Creates an instance of a damage function based on the parameters given
    :param parameters: the parameters
    :return: a new instance of a damage function
    """
    validate(instance=parameters, schema=damage_function_parameter_schema)

    if parameters['name'] == 'identity':
        return DamageFunctionIdentity()

    elif parameters['name'] == 'range':
        args = parameters['arguments']
        lower = float(args[0])
        upper = float(args[1])
        return DamageFunctionRange(lower, upper)

    elif parameters['name'] == 'step':
        args = parameters['arguments']
        limit_0 = float(args[0])
        limit_1 = float(args[1])
        limit_2 = float(args[2])
        value_0 = float(args[3])
        value_1 = float(args[4])
        value_2 = float(args[5])
        value_3 = float(args[6])
        return DamageFunctionStep(limit_0, limit_1, limit_2, value_0, value_1, value_2, value_3)


def determine_weights_map(exposure_map, weights: dict):
    """
    Determines a map of weights with the same shape as a given exposure map and given weights for
    each exposure mask. For example: weights={"1":0.9,"2":0.3} means exposure masks '1' and '2'
    have weight of 0.9 and 0.3, respectively. For an exposure map [1, 1, 1, 2, 2, 2], the resulting
    spatial weights map would thus be: [0.9, 0.9, 0.9, 0.3, 0.3, 0.3].
    :param exposure_map: a two-dimensional array whereby each cell indicates the mask id.
    :param weights: a simple mapping between mask id and weight.
    :return: an array with the same dimensions as the exposure map whereby each cell represents
    a weight.
    """

    exposure_map = np.array(exposure_map, dtype=int)

    m_values = []
    w_values = []
    for mask_id in weights:
        m_values.append(int(mask_id))
        w_values.append(weights[mask_id])

    # source: https://stackoverflow.com/questions/62183295/update-values-in-numpy-array-with-other-values-in-python
    N = max(exposure_map.max(), max(m_values))+1
    weights_map = np.empty(N, dtype=float)
    weights_map[exposure_map] = exposure_map
    weights_map[m_values] = w_values
    weights_map = weights_map[exposure_map]

    return weights_map


def convert_exposure_map(input_path, output_path):
    """
    Convert the exposure map input (a CSV file) into hdf5. The output file will also contain some attributes
    with meta information about the data: dimensions, description and mask_ids.
    :param input_path: path to CSV input file
    :param output_path: path to hdf5 output file
    :return:
    """
    try:
        reader = csv.reader(open(input_path, "r"), delimiter=",")
        # TODO: fix issue with --> ValueError: invalid literal for int() with base 10: '\ufeff0'
        data = np.array(list(reader)).astype(np.int8)

        # store as HDF5
        f = h5py.File(output_path, "w")
        dset = f.create_dataset("exposure_map", data=data)
        dset.attrs['dimensions'] = ['y', 'x']
        dset.attrs['description'] = "CS1.5 DSS-demo Exposure Map"
        dset.attrs['mask_ids'] = np.unique(data)
        f.close()
        return True

    except Exception as e:
        logger.error(f"input_path={input_path} output_path={output_path} e={e}")
        return False


def convert_climate_data(input_path, output_path, climate_variable, weather_type, n_time_steps=24, nan_value=-999):
    """
    Convert the climate data input (a CSV file) into hdf5. The output file will also contain some attributes
    with meta information about the data: dimensions, description, climate_variable, weather_type and unit.
    :param input_path: path to CSV input file
    :param output_path: path to hdf5 output file
    :param climate_variable: string indicating the climate variable (e.g., 'pet', 'at') used for meta information
    :param weather_type: string indicating the weather tpye (e.g., 'w0', 'w1') used for meta information
    :param n_time_steps: number of time steps (default: 24), i.e., the size of the time dimension
    :param nan_value: the NaN value (default: -999) used to be replaced with np.nan for correct calculations
    :return:
    """
    try:
        reader = csv.reader(open(input_path, "r"), delimiter=",")
        temp = np.array(list(reader)).astype(np.float32)

        # replace buildings (-999) with nan
        temp = np.where(temp == nan_value, np.nan, temp)

        # determine width and height
        width = temp.shape[1]
        height = int(temp.shape[0] / n_time_steps)
        if height * n_time_steps != temp.shape[0]:
            raise Exception(
                f"CSV file '{input_path}' has {temp.shape[0]} lines, "
                f"assuming {n_time_steps} timesteps, "
                f"the expected number of lines is {(height * n_time_steps)}"
            )
        # print(f"before reshaping: shape(temp)={temp.shape} height={height} width={width}")

        # do reshaping
        temp = temp.reshape((n_time_steps, height, width))
        # print(f"after reshaping: shape(temp)={temp.shape} height={height} width={width}")

        # store as HDF5
        f = h5py.File(output_path, "w")
        dset = f.create_dataset("climate_data", data=temp)
        dset.attrs['dimensions'] = ['time', 'y', 'x']
        dset.attrs['description'] = "CS1.5 DSS-demo Climate Data"
        dset.attrs['climate_variable'] = climate_variable
        dset.attrs['weather_type'] = weather_type
        dset.attrs['unit'] = "Celsius (˚C)"
        f.close()

        return True

    except Exception as e:
        logger.error(f"input_path={input_path} output_path={output_path} climate_variable={climate_variable} "
                     f"weather_type={weather_type} e={e}")
        return False

