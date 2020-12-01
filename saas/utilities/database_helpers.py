"""
Contains a number of helper functions and classes used throughout the SaaS Middleware.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import sqlite3

logger = logging.getLogger('Utilities.database_helpers')


class DBTable:
    """
    DBTable is a convenience base class that wraps a SQL table and provides simple access methods to perform common
    SQL commands: CREATE TABLE, DROP TABLE, SELECT, INSERT, UPDATE, DELETE. This class is not thread-safe.
    """
    def __init__(self, db_path, name):
        self.db_path = db_path
        self.name = name
        self.columns = []

    def create(self, definitions, unique=None):
        """
        Executes a CREATE TABLE statement.
        :param definitions: a dictionary containing column definition as {'column_name' : 'column_definition'}
        :param unique: a list of column names that are used for an optional UNIQUE() (default: None)
        :return: None
        """
        self.columns = [*definitions]

        col_string = ','.join("{} {}".format(col_name, col_type) for col_name, col_type in definitions.items())
        if unique:
            col_string = "{}, UNIQUE({})".format(col_string, ','.join(unique))

        db = sqlite3.connect(self.db_path)
        db.execute(
            "CREATE TABLE IF NOT EXISTS {} ({})".format(self.name, col_string)
        )
        db.close()

    def drop(self):
        """
        Executes a DROP TABLE statement.
        :return: None
        """
        db = sqlite3.connect(self.db_path)
        db.execute(
            "DROP TABLE {}".format(self.name)
        )
        db.commit()
        db.close()

    # TODO: where conditions should allow for more than just 'equals' comparisons (this applies to other statements too)
    def select(self, columns=None, where_parameters=None, use_distinct=False):
        """
        Executes a SELECT statement.
        :param columns: list of selected column names (if none provided, all columns are selected)
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :param use_distinct: indicate whether to use DISTINCT or not (default: False)
        :return: result of SQL query
        """
        if not columns:
            columns = self.columns

        col_names = ",".join(columns)

        db = sqlite3.connect(self.db_path)
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
        return records

    def insert(self, parameters, or_ignore=False):
        """
        Executes an INSERT statement.
        :param parameters: a dictionary containing {'column_name': 'value'}
        :param or_ignore: indicates whether to use OR IGNORE or not (default: False)
        :return: None
        """
        # create column names and values
        col_names = ",".join(parameters.keys())
        col_values = ','.join("'{}'".format(value)
                              if isinstance(value, str) else str(value)
                              for value in parameters.values())

        db = sqlite3.connect(self.db_path)
        db.execute("INSERT {} INTO {} ({}) VALUES ({})".format(
            'OR IGNORE' if or_ignore else '',
            self.name, col_names, col_values))
        db.commit()
        db.close()

    def update(self, update_parameters, where_parameters):
        """
        Executes an UPDATE statement.
        :param update_parameters: a dictionary containing {'column_name': 'new_value'}
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :return: None
        """
        update = ",".join("{}={}".format(key, "'{}'".format(value)
                          if isinstance(value, str) else value)
                          for key, value in update_parameters.items())

        where_clause = " AND ".join("{}={}".format(key, "'{}'".format(value)
                                    if isinstance(value, str) else value)
                                    for key, value in where_parameters.items())

        db = sqlite3.connect(self.db_path)
        db.execute("UPDATE {} SET {} WHERE {}".format(self.name, update, where_clause))
        db.commit()
        db.close()

    def delete(self, where_parameters=None):
        """
        Executes a DELETE statement.
        :param where_parameters: list of where conditions as {'column_name': 'equals_condition'}
        :return: None
        """
        db = sqlite3.connect(self.db_path)
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

    def get_number_of_rows(self):
        """
        Returns the number of rows in the table.
        :return: number of rows
        """
        db = sqlite3.connect(self.db_path)
        sql_result = db.execute("SELECT COUNT(*) FROM {}".format(self.name)).fetchone()
        result = int(sql_result[0])
        db.close()
        return result
