import os.path
from typing import Optional, List, Tuple
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from saas.core.logging import Logging
from sqlalchemy import Column, String, Boolean, create_engine, Integer
from sqlalchemy.orm import sessionmaker, declarative_base
from jose import jwt

from saas.core.helpers import generate_random_string
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.rest.schemas import Token
from saas.sdk.app.exceptions import AppRuntimeError
from saas.sdk.base import publish_identity

Base = declarative_base()
logger = Logging.get('saas.sdk.app')


class UserRecordV0(Base):
    __tablename__ = 'user'
    login = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    disabled = Column(Boolean, nullable=False)
    keystore_id = Column(String(64), nullable=False)
    keystore_password = Column(String, nullable=False)
    hashed_password = Column(String(64), nullable=False)


class UserRecordV1(Base):
    __tablename__ = 'user_v1'
    login = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    disabled = Column(Boolean, nullable=False)
    keystore_id = Column(String(64), nullable=False)
    keystore_password = Column(String, nullable=False)
    hashed_password = Column(String(64), nullable=False)
    login_attempts = Column(Integer, nullable=False)


UserRecord = UserRecordV1


class User(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    name: str
    login: str
    disabled: bool
    hashed_password: str
    keystore: Keystore
    login_attempts: int

    @property
    def identity(self) -> Identity:
        return self.keystore.identity


class UserDB:
    _keystore_path = None
    _engine = None
    _Session = None
    _keystores = {}

    @classmethod
    def initialise(cls, wd_path: str) -> None:
        # create directories
        cls._keystore_path = os.path.join(wd_path, 'keystores')
        os.makedirs(cls._keystore_path, exist_ok=True)

        # initialise database things
        db_path = f"sqlite:///{os.path.join(wd_path, 'user.db')}"
        cls._engine = create_engine(db_path)
        Base.metadata.create_all(cls._engine)
        cls._Session = sessionmaker(bind=cls._engine)

        # check if db records need to be migrated
        logger.info("check if user db records need to be migrated")
        cls.migrate_v0_to_v1()

    @classmethod
    def publish_all_user_identities(cls, node_address: (str, int)) -> None:
        for user in UserDB.all_users():
            publish_identity(node_address, user.identity)

    @classmethod
    def _resolve_keystore(cls, keystore_id: str, keystore_password: str) -> Keystore:
        if keystore_id not in cls._keystores:
            keystore_path = os.path.join(cls._keystore_path, f"{keystore_id}.json")
            cls._keystores[keystore_id] = Keystore.load(keystore_path, keystore_password)
        return cls._keystores[keystore_id]

    @classmethod
    def migrate_v0_to_v1(cls):
        """
        Migrate v0 user records (if any) to v1. Changes from v0 to v1:
        - introduce column login_attempts
        :return:
        """
        with cls._Session() as session:
            # do we have any v0 records?
            records = session.query(UserRecordV0).all()
            if len(records) > 0:
                logger.warning(f"found {len(records)} v0 user records -> migrating to v1...")

                # migrate all records -> add v1 record and delete v0 record
                for record in records:
                    # add users to the v1 table
                    session.add(UserRecordV1(login=record.login, name=record.name, disabled=record.disabled,
                                             keystore_id=record.keystore_id, keystore_password=record.keystore_password,
                                             hashed_password=record.hashed_password,
                                             login_attempts=0))

                    # remove users from v0 table
                    session.query(UserRecordV0).filter_by(login=record.login).delete()

                session.commit()

            else:
                logger.info("no v0 user records found.")

    @classmethod
    def get_user(cls, login: str) -> Optional[User]:
        with cls._Session() as session:
            record = session.query(UserRecord).get(login)
            if record:
                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )

            else:
                return None

    @classmethod
    def delete_user(cls, login: str) -> User:
        with cls._Session() as session:
            q = session.query(UserRecord).filter_by(login=login)

            # does the user exist?
            record = q.first()
            if not record:
                raise AppRuntimeError("User account does not exist", details={
                    'login': login
                })

            # create the user object
            result = User(
                login=record.login,
                name=record.name,
                disabled=record.disabled,
                hashed_password=record.hashed_password,
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                login_attempts=record.login_attempts
            )

            # remove the keystore and delete it
            cls._resolve_keystore(record.keystore_id, record.keystore_password)
            keystore = cls._keystores.pop(record.keystore_id)
            keystore.delete()

            # remove the record
            q.delete()
            session.commit()

            return result

    @classmethod
    def all_users(cls) -> List[User]:
        with cls._Session() as session:
            records = session.query(UserRecord).all()
            return [User(
                login=record.login,
                name=record.name,
                disabled=record.disabled,
                hashed_password=record.hashed_password,
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                login_attempts=record.login_attempts
            ) for record in records]

    @classmethod
    def add_user(cls, login: str, name: str, password: str, node_address: (str, int) = None) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                raise AppRuntimeError("User account already exists", details={
                    'login': login
                })

            # create a new keystore
            keystore_password = generate_random_string(16)
            keystore = Keystore.create(cls._keystore_path, name, login, keystore_password)
            cls._keystores[keystore.identity.id] = keystore

            # add new user (with a randomly generated password)
            disabled = False
            hashed_password = UserAuth.get_password_hash(password)
            session.add(UserRecord(login=login, name=name, disabled=disabled,
                                   keystore_id=keystore.identity.id, keystore_password=keystore_password,
                                   hashed_password=hashed_password, login_attempts=0))
            session.commit()

            # publish the identity (if we have a node address)
            if node_address:
                publish_identity(node_address, keystore.identity)

            # read the record and return the user
            return User(
                login=login,
                name=name,
                disabled=disabled,
                hashed_password=hashed_password,
                keystore=keystore,
                login_attempts=0
            )

    @classmethod
    def enable_user(cls, login: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                record.disabled = False
                record.login_attempts = 0
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def disable_user(cls, login: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                record.disabled = True
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def update_user(cls, login: str, is_admin: bool, password: Tuple[str, str] = None,
                    user_display_name: str = None) -> User:
        with cls._Session() as session:
            # check if this username exists
            record = session.query(UserRecord).get(login)
            if record:
                # do we have a new display name? if so, update the record.
                if user_display_name:
                    record.name = user_display_name

                # do we have a new password? if so, check privileges first, then update it.
                if password:
                    # if we are not admin, we need to have a matching password
                    if not is_admin:
                        # verify if the hashes of the current password match
                        if not UserAuth.verify_password(password[0], record.hashed_password):
                            raise AppRuntimeError("Password does not match", details={
                                'login': login
                            })

                    # at this point we are either admin or we have a matching password -> update the record
                    record.hashed_password = UserAuth.get_password_hash(password[1])

                # update the user record and return and updated user object
                session.commit()
                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )

            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def update_login_attempts(cls, login: str, successful: bool) -> User:
        with cls._Session() as session:
            # check if this username exists
            record = session.query(UserRecord).get(login)
            if record:
                # update the attempt counter (reset to zero if successful)
                record.login_attempts = 0 if successful else record.login_attempts + 1
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })


class UserAuth:
    secret_key = None
    algorithm = 'HS256'
    _access_token_expires_minutes = 30
    _max_login_attempts = 5
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def initialise(cls, secret_key: str):
        cls.secret_key = secret_key

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return cls._pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return cls._pwd_context.hash(password)

    @classmethod
    async def login_for_access_token(cls, form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
        # do we have a user object?
        user = UserDB.get_user(form_data.username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # is the user account disabled?
        if user.disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account disabled. Please contact administrator.",
                headers={"WWW-Authenticate": "Locked"},
            )

        # verify the password and update the login attempt counter
        valid_password = cls.verify_password(form_data.password, user.hashed_password)
        user = UserDB.update_login_attempts(form_data.username, valid_password)

        # was password verification successful? if not, raise an error
        if not valid_password:
            # have login attempts exceeded the limit? disable account
            if user.login_attempts >= cls._max_login_attempts:
                UserDB.disable_user(form_data.username)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # create the token
        now = datetime.now(tz=timezone.utc)
        expiry = now + timedelta(minutes=cls._access_token_expires_minutes)
        content = {
            'sub': user.login,
            'exp': expiry
        }
        access_token = jwt.encode(content, cls.secret_key, algorithm=cls.algorithm)

        token = Token(access_token=access_token, token_type='bearer', expiry=expiry.timestamp())
        return token
