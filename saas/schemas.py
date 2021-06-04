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
            'owner_public_key': {'type': 'string'},
            'restricted_access': {'type': 'boolean'},
            'content_encrypted': {'type': 'boolean'}
        },
        'required': ['name', 'owner_public_key', 'restricted_access', 'content_encrypted']
    }
}

task_descriptor_schema = {
    'type': 'object',
    'properties': {
        'processor_id': {'type': 'string'},
        'input': input_interface_schema,
        'output': output_interface_schema,
        'user_public_key': {'type': 'string'}
    },
    'required': ['processor_id', 'input', 'output', 'user_public_key']
}

# wf_task_descriptor_schema = {
#     'type': 'object',
#     'properties': {
#         'name': {'type': 'string'},
#         'processor_id': {'type': 'string'},
#         'input': input_interface_schema,
#         'output': output_interface_schema
#     },
#     'required': ['name', 'processor_id', 'input', 'output']
# }

# io_mapping_schema = {
#     'type': 'object',
#     'properties': {
#         'from':  {'type': 'string'},
#         'to': {'type': 'string'}
#     },
#     'required': ['from', 'to']
# }

# workflow_descriptor_schema = {
#     'type': 'object',
#     'properties': {
#         'name': {'type': 'string'},
#         'tasks': {
#             'type': 'array',
#             'items': wf_task_descriptor_schema
#         }
#     },
#     'required': ['name', 'tasks']
# }

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

# processor_descriptor_schema = {
#     'type': 'object',
#     'properties': {
#         'created_t': {'type': 'number'},
#         'created_by': {'type': 'string'},
#     },
#     'required': ['created_t', 'created_by']
# }

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

git_specification_schema = {
    'type': 'object',
    'properties': {
        'source': {'type': 'string'},
        'commit_id': {'type': 'string'},
        'proc_path': {'type': 'string'},
        'proc_descriptor': processor_descriptor_schema
    },
    'required': ['source', 'commit_id', 'path', 'proc_descriptor']
}
