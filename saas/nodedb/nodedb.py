"""
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import sqlite3
import os

from threading import Lock

from saas.nodedb.protocol import NodeDBP2PProtocol

logger = logging.getLogger('NodeDB.NodeDB')


class DBTable:
    """
    DBTable is a convenience base class that wraps a SQL table and provides simple access methods to perform common
    SQL commands: CREATE TABLE, DROP TABLE, SELECT, INSERT, UPDATE, DELETE. This class is not thread-safe.
    """
    def __init__(self, node_db, name, columns, auto_sync):
        self.mutex = Lock()
        self.node_db = node_db
        self.name = name
        self.columns = columns
        self.auto_sync = auto_sync

    # TODO: where conditions should allow for more than just 'equals' comparisons (this applies to other statements too)
    def select(self, columns=None, where_parameters=None, use_distinct=False):
        """
        Executes a SELECT statement.
        :param columns: list of selected column names (if none provided, all columns are selected)
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :param use_distinct: indicate whether to use DISTINCT or not (default: False)
        :return: result of SQL query
        """
        self.mutex.acquire()
        if not columns:
            columns = self.columns

        col_names = ",".join(columns)

        db = sqlite3.connect(self.node_db.db_path)
        if where_parameters:
            where_clause = " AND ".join(
                "{}={}".format(key, "'{}'".format(value) if isinstance(value, str) else value) for key, value in
                where_parameters.items()
            )
            rows = db.execute(
                    "SELECT {} {} FROM {} WHERE {}".format("DISTINCT" if use_distinct else "", col_names, self.name,
                                                           where_clause)
            )

        else:
            rows = db.execute(
                    "SELECT {} {} FROM {}".format("DISTINCT" if use_distinct else "", col_names, self.name)
            )

        # build records
        records = []
        for row in rows:
            record = {}
            for i in range(0, len(columns)):
                record[columns[i]] = row[i]
            records.append(record)

        db.close()
        self.mutex.release()
        return records

    def insert(self, parameters, or_ignore=False, propagate=True):
        """
        Executes an INSERT statement.
        :param parameters: a dictionary containing {'column_name': 'value'}
        :param or_ignore: indicates whether to use OR IGNORE or not (default: False)
        :param propagate: indicates whether to propagate this SQL action to other nodes (default: True)
        :return: None
        """
        self.mutex.acquire()
        col_names = ",".join(parameters.keys())
        col_values = ','.join("'{}'".format(value)
                              if isinstance(value, str) else str(value)
                              for value in parameters.values())

        db = sqlite3.connect(self.node_db.db_path)
        db.execute("INSERT {} INTO {} ({}) VALUES ({})".format(
            'OR IGNORE' if or_ignore else '',
            self.name, col_names, col_values))
        db.commit()
        db.close()

        # queue the update for synchronisation purposes
        if self.auto_sync and propagate:
            self.node_db.queue_insert(self.name, parameters, or_ignore)
        self.mutex.release()

    def update(self, update_parameters, where_parameters, propagate=True):
        """
        Executes an UPDATE statement.
        :param update_parameters: a dictionary containing {'column_name': 'new_value'}
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :param propagate: indicates whether to propagate this SQL action to other nodes (default: True)
        :return: None
        """
        self.mutex.acquire()
        update = ",".join("{}={}".format(key, "'{}'".format(value)
                          if isinstance(value, str) else value)
                          for key, value in update_parameters.items())

        where_clause = " AND ".join("{}={}".format(key, "'{}'".format(value)
                                    if isinstance(value, str) else value)
                                    for key, value in where_parameters.items())

        db = sqlite3.connect(self.node_db.db_path)
        db.execute("UPDATE {} SET {} WHERE {}".format(self.name, update, where_clause))
        db.commit()
        db.close()

        # queue the update for synchronisation purposes
        if self.auto_sync and propagate:
            self.node_db.queue_update(self.name, update_parameters, where_parameters)
        self.mutex.release()

    def delete(self, where_parameters=None, propagate=True):
        """
        Executes a DELETE statement.
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :param propagate: indicates whether to propagate this SQL action to other nodes (default: True)
        :return: None
        """
        self.mutex.acquire()
        db = sqlite3.connect(self.node_db.db_path)
        if where_parameters:
            # create where clause
            where_clause = " AND ".join(
                "{}={}".format(key, "'{}'".format(value) if isinstance(value, str) else value) for key, value in
                where_parameters.items()
            )

            db.execute(
                "DELETE FROM {} WHERE {}".format(self.name, where_clause)
            )
        else:
            db.execute(
                "DELETE FROM {}".format(self.name)
            )
        db.commit()
        db.close()

        # queue the update for synchronisation purposes
        if self.auto_sync and propagate:
            self.node_db.queue_delete(self.name, where_parameters)
        self.mutex.release()

    def get_number_of_rows(self):
        """
        Returns the number of rows in the table.
        :return: number of rows
        """
        self.mutex.acquire()
        db = sqlite3.connect(self.node_db.db_path)
        sql_result = db.execute("SELECT COUNT(*) FROM {}".format(self.name)).fetchone()
        result = int(sql_result[0])
        db.close()
        self.mutex.release()
        return result


class NodeDB:
    def __init__(self, node, immediate_updates=True):
        self.mutex = Lock()
        self.node = node
        self.tables = {}
        self.db_path = os.path.join(node.datastore_path, 'records.db')
        self.immediate_updates = immediate_updates
        self.queue = []

    def create_table(self, name, definitions, unique=None, auto_sync=False):
        self.mutex.acquire()
        columns = [*definitions]

        col_string = ','.join("{} {}".format(col_name, col_type) for col_name, col_type in definitions.items())
        if unique:
            col_string = "{}, UNIQUE({})".format(col_string, ','.join(unique))

        db = sqlite3.connect(self.db_path)
        db.execute(
            "CREATE TABLE IF NOT EXISTS {} ({})".format(name, col_string)
        )
        db.close()

        self.mutex.release()
        self.tables[name] = DBTable(self, name, columns, auto_sync)
        return self.tables[name]

    def drop_table(self, name):
        """
        Executes a DROP TABLE statement.
        :return: None
        """
        self.mutex.acquire()
        if name in self.tables:
            db = sqlite3.connect(self.db_path)
            db.execute(
                "DROP TABLE {}".format(name)
            )
            db.commit()
            db.close()
            self.tables.pop(name)
        self.mutex.release()

    def queue_insert(self, table_name, parameters, or_ignore):
        self.mutex.acquire()
        self.queue.append({
            'action': 'sql_insert',
            'table_name': table_name,
            'parameters': parameters,
            'or_ignore': or_ignore
        })
        self.mutex.release()

        if self.immediate_updates:
            self.broadcast_updates()

    def queue_update(self, table_name, update_parameters, where_parameters):
        self.mutex.acquire()
        self.queue.append({
            'action': 'sql_update',
            'table_name': table_name,
            'update_parameters': update_parameters,
            'where_parameters': where_parameters
        })
        self.mutex.release()

        if self.immediate_updates:
            self.broadcast_updates()

    def queue_delete(self, table_name, where_parameters):
        self.mutex.acquire()
        self.queue.append({
            'action': 'sql_delete',
            'table_name': table_name,
            'where_parameters': where_parameters
        })
        self.mutex.release()

        if self.immediate_updates:
            self.broadcast_updates()

    def broadcast_updates(self):
        self.mutex.acquire()
        queue = self.queue
        self.queue = []
        self.mutex.release()

        protocol = self.node.msg_protocols[NodeDBP2PProtocol.id]
        protocol.broadcast_updates(queue)

    def handle_updates(self, items):
        for item in items:
            table: DBTable = self.tables[item['table_name']]
            if item['action'] == 'sql_insert':
                table.insert(item['parameters'], item['or_ignore'], False)

            elif item['action'] == 'sql_update':
                table.update(item['update_parameters'], item['where_parameters'], False)

            elif item['action'] == 'sql_delete':
                table.delete(item['where_parameters'], False)
