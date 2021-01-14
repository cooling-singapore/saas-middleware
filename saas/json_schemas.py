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
                'obj_id': {'type': 'string'}
            }
        },
        'else': {
            'properties': {
                'value': {'type': 'string'},
                'data_type': {'type': 'string'},
                'data_format': {'type': 'string'},
            }
        },
    }
}

output_interface_schema = {
    'type': 'object',
    'properties': {
        'owner_public_key': {'type': 'string'}
        # 'visibility': {'type': 'string', 'enum': ['private', 'domain', 'public']},
    },
    'required': ['owner_public_key']
}

task_descriptor_schema = {
    'type': 'object',
    'properties': {
        'processor_id': {'type': 'string'},
        'input': input_interface_schema,
        'output': output_interface_schema
    },
    'required': ['processor_id', 'input', 'output']
}

wf_task_descriptor_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'processor_id': {'type': 'string'},
        'input': input_interface_schema,
        'output': output_interface_schema
    },
    'required': ['name', 'processor_id', 'input', 'output']
}

io_mapping_schema = {
    'type': 'object',
    'properties': {
        'from':  {'type': 'string'},
        'to': {'type': 'string'}
    },
    'required': ['from', 'to']
}

workflow_descriptor_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'tasks': {
            'type': 'array',
            'items': wf_task_descriptor_schema
        }
    },
    'required': ['name', 'tasks']
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
        'data_format': {'type': 'string', 'enum': ['json']}
    },
    'required': ['name', 'data_type', 'data_format']
}

processor_descriptor_schema = {
    'type': 'object',
    'properties': {
        'name': {'type': 'string'},
        'version': {'type': 'string'},
        'type': {'type': 'string', 'enum': ['docker', 'package', 'script']},
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
