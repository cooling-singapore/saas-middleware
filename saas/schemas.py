input_interface_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'type': {'type': 'string', 'enum': ['reference', 'value']},
        },
        'if': {
            'properties': {'type': {'const': 'reference'}}
        },
        'then': {
            'properties': {
                'obj_id': {'type': 'string'},
                'access_token': {'type': 'string'}
            }
        },
        'else': {
            'properties': {
                'value': {'type': 'object'}
            }
        },
        'required': ['name', 'type']
    }
}

output_interface_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'owner_iid': {'type': 'string'},
            'restricted_access': {'type': 'boolean'},
            'content_encrypted': {'type': 'boolean'},
            'target_node_iid': {'type': 'string'}
        },
        'required': ['name', 'owner_iid', 'restricted_access', 'content_encrypted']
    }
}

task_descriptor_schema = {
    'type': 'object',
    'properties': {
        'processor_id': {'type': 'string'},
        'input': input_interface_schema,
        'output': output_interface_schema,
        'user_iid': {'type': 'string'}
    },
    'required': ['processor_id', 'input', 'output', 'user_iid']
}

io_variable_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'data_type': {'type': 'string'},
        'data_format': {'type': 'string'}
    },
    'if': {
        'properties': {'data_type': {'const': 'JSONObject'}}
    },
    'then': {
        'properties': {
            'schema': {'type': 'object'}
        }
    },
    'required': ['name', 'data_type', 'data_format']
}

processor_descriptor_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'input': {
            'type': 'array',
            'items': io_variable_schema
        },
        'output': {
            'type': 'array',
            'items': io_variable_schema
        },
        'configurations': {
            'type': 'array',
            'items': {'type': 'string'}
        }
    },
    'required': ['name', 'input', 'output', 'configurations']
}

git_proc_pointer_schema = {
    'type': 'object',
    'properties': {
        'source': {'type': 'string'},
        'commit_id': {'type': 'string'},
        'proc_path': {'type': 'string'},
        'proc_config': {'type': 'string'},
        'proc_descriptor': {'type': 'object'}
    },
    'required': ['source', 'commit_id', 'proc_path', 'proc_config']
}

network_node_schema = {
    'type': 'object',
    'properties': {
        'iid': {'type': 'string'},
        'last_seen': {'type': 'number'},
        'p2p_address': {'type': 'string'},
        'rest_address': {'type': 'string'},
        'dor_service': {'type': 'boolean'},
        'rti_service': {'type': 'boolean'}
    },
    'required': ['iid', 'last_seen', 'p2p_address', 'dor_service', 'rti_service']
}

job_descriptor_schema = {
    'type': 'object',
    'properties': {
        'id': {'type': 'string'},
        'proc_id': {'type': 'string'},
        'task': task_descriptor_schema
    },
    'required': ['id', 'proc_id', 'task']
}

recipe_schema = {
    'type': 'object',
    'properties': {
        'product': {
            'type': 'object',
            'properties': {
                'name': {'type': 'string'},
                'c_hash': {'type': 'string'},
                'data_type': {'type': 'string'},
                'data_format': {'type': 'string'}
            },
            'required': ['name', 'c_hash', 'data_type', 'data_format']
        },
        'processor': {
            'type': 'object',
            'properties': {
                'proc_id': {'type': 'string'},
                'gpp': git_proc_pointer_schema
            },
            'required': ['proc_id', 'gpp']
        },
        'input': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'data_type': {'type': 'string'},
                    'data_format': {'type': 'string'},
                    'type': {'type': 'string', 'enum': ['reference', 'value']}
                },
                'if': {
                    'properties': {'type': {'const': 'reference'}}
                },
                'then': {
                    'properties': {
                        'c_hash': {'type': 'string'}
                    }
                },
                'else': {
                    'properties': {
                        'value': {'type': 'object'}
                    }
                },
                'required': ['name', 'data_type', 'data_format', 'type']
            }
        }
    },
    'required': ['product', 'processor', 'input']
}

provenance_schema = {
    'type': 'object',
    'properties': {
        'content_nodes': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'c_hash': {'type': 'string'},
                    'type': {'type': 'string', 'enum': ['original', 'derived']},
                    'data_type': {'type': 'string'},
                    'data_format': {'type': 'string'}
                },
                'required': ['c_hash', 'type', 'data_type', 'data_format']
            }
        },
        'proc_nodes': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'gpp_hash': {'type': 'string'},
                    'gpp': git_proc_pointer_schema,
                },
                'required': ['gpp_hash', 'gpp']
            }
        },
        'steps': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'consume': {'type': 'array', 'items': {'type': 'string'}},
                    'processor': {'type': 'string'},
                    'produce': {'type': 'string'}
                },
                'required': ['consume']
            }
        }
    }
}
