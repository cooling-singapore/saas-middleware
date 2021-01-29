import csv
import h5py
import numpy as np

from jsonschema import validate

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


def determine_spatial_weights_map(exposure_map, weights: dict):
    """
    Determines a map of weights with the same shape as a given exposure map. The weights are
    selected based on which exposure mask is selected and its corresponding weight.
    For example: weights={"1":0.9,"2":1.0} means exposure masks '1' and '2' have weight of 0.9
    and 1.0, respectively. If mask "1" is selected, then a weight of 0.9 is chosen.
    """

    spatial_weights_map = np.zeros(exposure_map.shape, dtype=float)
    height = spatial_weights_map.shape[0]
    width = spatial_weights_map.shape[1]
    for y in range(0, height):
        for x in range(0, width):
            exp_mask_id = str(exposure_map[y, x])
            spatial_weights_map[y, x] = weights[exp_mask_id] if exp_mask_id in weights else 0

    return spatial_weights_map


def convert_exposure_map(input_path, output_path):
    reader = csv.reader(open(input_path, "r"), delimiter=",")
    temp = np.array(list(reader)).astype(np.int8)

    # determine width and height
    width = temp.shape[1]
    height = temp.shape[0]
    # if height * n_time_steps != temp.shape[0]:
    #     raise Exception(
    #         f"CSV file '{input_path}' has {temp.shape[0]} lines, "
    #         f"assuming {n_time_steps} timesteps, "
    #         f"the expected number of lines is {(height * n_time_steps)}"
    #     )
    # print(f"before reshaping: shape(temp)={temp.shape} height={height} width={width}")

    # do reshaping
    # temp = temp.reshape((n_time_steps, height, width))
    # print(f"after reshaping: shape(temp)={temp.shape} height={height} width={width}")

    mask_ids = np.unique(temp)

    # store as HDF5
    f = h5py.File(output_path, "w")
    dset = f.create_dataset("exposure_map", data=temp)
    dset.attrs['dimensions'] = ['y', 'x']
    dset.attrs['description'] = "CS1.5 DSS-demo Exposure Map"
    dset.attrs['mask_ids'] = mask_ids
    f.close()


def convert_climate_data(input_path, output_path, climate_variable, weather_type, n_time_steps=24, nan_value=-999):
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
    print(f"before reshaping: shape(temp)={temp.shape} height={height} width={width}")

    # do reshaping
    temp = temp.reshape((n_time_steps, height, width))
    print(f"after reshaping: shape(temp)={temp.shape} height={height} width={width}")

    # store as HDF5
    f = h5py.File(output_path, "w")
    dset = f.create_dataset("climate_data", data=temp)
    dset.attrs['dimensions'] = ['time', 'y', 'x']
    dset.attrs['description'] = "CS1.5 DSS-demo Climate Data"
    dset.attrs['climate_variable'] = climate_variable
    dset.attrs['weather_type'] = weather_type
    dset.attrs['unit'] = "Celsius (˚C)"
    f.close()
