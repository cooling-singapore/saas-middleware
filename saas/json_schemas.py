job_descriptor_schema = {
    'type': 'object',
    'properties': {
        'processor_id': {'type': 'string'},
        'input': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'type': {'type': 'string', 'enum': ['reference', 'value']},
                    'value': {'type': 'string'}
                }
            }
        },
        'output': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'name': {'type': 'string'},
                    'visibility': {'type': 'string', 'enum': ['private', 'domain', 'public']},
                    'owner_public_key': {'type': 'string'}
                }
            }
        }
    },
    'required': ['processor_id', 'input', 'output']
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
                'job_descriptor': job_descriptor_schema,
                'output_name': {'type': 'string'}
            },
            'required': ['job_descriptor', 'output_name']
        }
    },
    'required': ['data_type', 'data_format', 'created_t', 'created_by', 'recipe']
}

io_variable_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'data_type': {'type': 'string'},
        'data_format': {'type': 'string', 'enum': ['json']}
    },
    'required': ['name', 'data_type', 'data_format']
}


processor_descriptor_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'version': {'type': 'string'},
        'type': {'type': 'string', 'enum': ['docker', 'package']},
        'input': {
            'type': 'array',
            'items': io_variable_schema
        },
        'output': {
            'type': 'array',
            'items': io_variable_schema
        }
    },
    'required': ['name', 'version', 'type', 'input', 'output']
}
