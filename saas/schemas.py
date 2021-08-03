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

data_object_descriptor_schema = {
    'type': 'object',
    'properties': {
        'data_type': {'type': 'string'},
        'data_format': {'type': 'string'},
        'created_t': {'type': 'number'},
        'created_by': {'type': 'string'},
        'recipe': {
            'type': 'object',
            'properties': {
                'task_descriptor': task_descriptor_schema,
                'output_name': {'type': 'string'}
            },
            'required': ['task_descriptor', 'output_name']
        }
    },
    'required': ['data_type', 'data_format', 'created_t', 'created_by']
}

io_variable_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'data_type': {'type': 'string'},
        'data_format': {'type': 'string'}
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
        }
    },
    'required': ['name', 'input', 'output']
}

git_auth_schema = {
    'type': 'object',
    'properties': {
        'username': {'type': 'string'},
        'password': {'type': 'string'}
    },
    'required': ['username', 'password']
}

ssh_auth_schema = {
    'type': 'object',
    'properties': {
        'login': {'type': 'string'},
        'key': {'type': 'string'}
    },
    'required': ['username', 'password']
}

git_proc_pointer_schema = {
    'type': 'object',
    'properties': {
        'source': {'type': 'string'},
        'commit_id': {'type': 'string'},
        'proc_path': {'type': 'string'},
        'proc_config': {'type': 'string'}
    },
    'required': ['source', 'commit_id', 'proc_path', 'proc_config']
}
