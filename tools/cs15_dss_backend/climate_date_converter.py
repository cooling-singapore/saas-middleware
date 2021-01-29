import os
import csv
import json
import requests
import h5py
import getpass
import numpy as np

from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import get_timestamp_now
from saas.utilities.blueprint_helpers import create_authentication, create_authorisation




source_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.csv"
destination_path = "/Users/heikoaydt/Desktop/attachment/climate_data/pet_w0.hdf5"
convert_data(source_path, destination_path, "PET", "W0")


# private_key_path = input("Enter path for identity: ")
private_key_path = "/Users/heikoaydt/Desktop/identity.pem"
password = 'password'
# password = getpass.getpass("Enter password for identity: ")

address = "127.0.0.1:5001"
# address = input("Enter DOR address (e.g., 127.0.0.1:5000): ")

if os.path.isfile(private_key_path):
    owner = ECKeyPair.from_private_key_file(private_key_path, password)
    print(f"existing identity found. using iid '{owner.iid}' and public key:\n{owner.public_as_string(truncate=False)}")

    print(f"uploading converted data object...")
    obj_id = upload(address, destination_path, owner, owner, 'heiko')
    print(f"data object id: {obj_id}")

    update_tags(address, owner, owner, obj_id, {
        'scenario': 'cbd_s51',
        'climatic_variable': 'pet',
        'weather_type': 'w0'
    })

else:
    print(f"no identity found at '{private_key_path}'")


