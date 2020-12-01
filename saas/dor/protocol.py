"""
This module contains the code for the Data Object Repository P2P protocol.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from saas.secure_messenger import MessengerProtocol
from saas.utilities.database_helpers import DBTable

logger = logging.getLogger('DOR.Protocol')


class DataObjectRepositoryP2PProtocol(MessengerProtocol):
    def __init__(self, node):
        super().__init__(node, "dor_records", {
            'insert': self.handle_insert,
            'update': self.handle_update,
            'delete': self.handle_delete
        })

    def broadcast_insert(self, table_name, parameters, or_ignore=False):
        # create the insert message
        message = self.prepare_message("insert", {
            'table_name': table_name,
            'parameters': parameters,
            'or_ignore': or_ignore
        })

        # broadcast the message
        self.broadcast_message(message)

    def broadcast_update(self, table_name, update_parameters, where_parameters):
        # create the insert message
        message = self.prepare_message("update", {
            'table_name': table_name,
            'update_parameters': update_parameters,
            'where_parameters': where_parameters
        })

        # broadcast the message
        self.broadcast_message(message)

    def broadcast_delete(self, table_name, where_parameters):
        # create the insert message
        message = self.prepare_message("delete", {
            'table_name': table_name,
            'where_parameters': where_parameters
        })

        # broadcast the message
        self.broadcast_message(message)

    def handle_insert(self, message, messenger):
        table = DBTable(self.node.dor.db_path, message['table_name'])
        table.insert(
            message['parameters'],
            message['or_ignore']
        )
        return True

    def handle_update(self, message, messenger):
        table = DBTable(self.node.dor.db_path, message['table_name'])
        table.update(
            message['update_parameters'],
            message['where_parameters']
        )
        return True

    def handle_delete(self, message, messenger):
        table = DBTable(self.node.dor.db_path, message['table_name'])
        table.delete(
            message['where_parameters']
        )
        return True

# if 'request' not in message:
#     logger.error("malformed message: {}".format(message))
#
# elif message['request'] == 'fetch':
#     obj_id = message['obj_id']
#
#     # check if we have the data object
#     record = self.db.get_data_object_by_id(obj_id)
#     source_path = os.path.join(self.datastore_path, "{}.content".format(record['c_hash']))
#     if os.path.isfile(source_path):
#         messenger.send({
#             'reply': 'found',
#             'obj_id': obj_id
#         })
#
#         messenger.send_attachment(source_path)
#
#     else:
#         messenger.send({
#             'reply': 'not found',
#             'obj_id': obj_id
#         })
#
# elif message['request'] == 'migrate':
#     pass
#
# else:
#     logger.error("unsupported request '{}': message={}".format(message['request'], message))
