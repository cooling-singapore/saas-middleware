import os
import sqlite3

from werkzeug.security import generate_password_hash

from saas.eckeypair import ECKeyPair, hash_bytes_object

USER_TABLE_NAME = 'users'
USER_GROUP_TABLE_NAME = 'user_groups'
KEY_TABLE_NAME = 'keys'
GROUP_MEMBERSHIP_TABLE_NAME = 'group_membership'


class AppDB:
    def __init__(self, db_path):
        self.db_path = db_path

        self.users = UserTable(self, USER_TABLE_NAME)
        self.keys = KeyTable(self, KEY_TABLE_NAME)
        self.user_groups = UserGroupTable(self, USER_GROUP_TABLE_NAME)
        self.group_membership = GroupMembershipTable(self, GROUP_MEMBERSHIP_TABLE_NAME)

        self._create_superuser()

    def _create_superuser(self, username='admin', password='password'):
        if self.users.get_user(username) is None:
            self.users.create_user(username, password)
        user = self.users.get_user(username)

        if self.user_groups.get_group('admin') is None:
            self.user_groups.create_group('admin')
        group = self.user_groups.get_group('admin')

        self.group_membership.assign_user(user['user_id'], group['group_id'])


class DBTable:
    def __init__(self, app_db: AppDB, name: str):
        self.app_db = app_db
        self.name = name
        self._create_table()

    @staticmethod
    def dict_from_row(row: sqlite3.Row):
        return dict(zip(row.keys(), row))

    def _create_table(self):
        raise NotImplementedError


class UserTable(DBTable):
    def _create_table(self):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {self.name} ("
                         f"user_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                         f"username TEXT NOT NULL UNIQUE,"
                         f"password TEXT NOT NULL );")

    def _empty_table(self):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {self.name};")
        self._create_table()

    def get_user(self, username):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(f"SELECT * FROM {self.name} WHERE username=:username;",
                                  {"username": username}).fetchone()
        if result is None:
            return None

        return self.dict_from_row(result)

    def get_user_by_id(self, user_id):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(f"SELECT * FROM {self.name} WHERE user_id=:user_id;",
                                  {"user_id": user_id}).fetchone()
        if result is None:
            return None

        return self.dict_from_row(result)

    def create_user(self, username, password):
        password_hash = generate_password_hash(password)
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"INSERT INTO {self.name} (username, password)"
                         f"VALUES (:username, :password);",
                         {"username": username,
                          "password": password_hash})

    def delete_user(self, username):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"DELETE FROM {self.name} WHERE username=:username;",
                         {"username": username})

    def update_user_password(self, username, new_password):
        pass


class UserGroupTable(DBTable):
    def _create_table(self):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {self.name} ("
                         f"group_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                         f"name TEXT NOT NULL UNIQUE,"
                         f"description TEXT,"
                         f"key_id TEXT NOT NULL,"
                         f"FOREIGN KEY (key_id) REFERENCES {KEY_TABLE_NAME} (key_id));")

    def create_group(self, group_name, description=None):
        key_id = self.app_db.keys.create_key('group_name', 'password')

        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"INSERT INTO {self.name} (name, description, key_id)"
                         f"VALUES (:name, :description, :key_id);",
                         {"name": group_name,
                          "description": description,
                          "key_id": key_id})

    def get_group(self, group_name):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(f"SELECT * FROM {self.name} WHERE name=:group_name;",
                                  {"group_name": group_name}).fetchone()
        if result is None:
            return None

        return self.dict_from_row(result)


class KeyTable(DBTable):
    def _create_table(self):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {self.name} ("
                         f"key_id TEXT NOT NULL PRIMARY KEY,"
                         f"name TEXT NOT NULL UNIQUE,"
                         f"description TEXT,"
                         f"private_key BLOB NOT NULL);")

    def create_key(self, key_name, password, description=None):
        key = ECKeyPair.create_new()
        private_key = key.private_as_bytes(password)
        # FIXME: Maybe key_id should not be the hash in the case where the key needs to be replaced
        key_id = hash_bytes_object(private_key)

        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"INSERT INTO {self.name} (key_id, name, description, private_key)"
                         f"VALUES (:key_id, :name, :description, :private_key);",
                         {"key_id": key_id,
                          "name": key_name,
                          "description": description,
                          "private_key": private_key})

        return key_id

    def get_key(self, key_name):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(f"SELECT * FROM {self.name} WHERE name=:key_name;",
                                  {"key_name": key_name}).fetchone()
        if result is None:
            return None

        return self.dict_from_row(result)


class GroupMembershipTable(DBTable):
    def _create_table(self):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {self.name} ("
                         f"group_id INTEGER NOT NULL,"
                         f"user_id INTEGER NOT NULL,"
                         f"PRIMARY KEY (group_id, user_id),"
                         f"FOREIGN KEY (group_id) REFERENCES {GROUP_MEMBERSHIP_TABLE_NAME} (group_id),"
                         f"FOREIGN KEY (user_id) REFERENCES {USER_TABLE_NAME} (user_id));")

    def assign_user(self, user_id, group_id):
        with sqlite3.connect(self.app_db.db_path) as conn:
            conn.execute(f"INSERT INTO {self.name} (user_id, group_id)"
                         f"VALUES (:user_id, :group_id);",
                         {"user_id": user_id,
                          "group_id": group_id})
