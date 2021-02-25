import os

from flask import Flask, jsonify
import logging

from flask_jwt_extended import JWTManager

from apps.dashboard.server.config import UserConfig, DefaultConfig
from apps.dashboard.server.database.db import AppDB
from apps.dashboard.server.login.blueprint import init_login

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('AppServer')


def init_app_server():
    config = get_config()
    app = create_app(config)
    # app.run(ssl_context='adhoc')
    app.run()


def get_config():
    if 'APP_SERVER_CONFIG' in os.environ:
        config_path = os.environ['APP_SERVER_CONFIG']
        config = UserConfig
        config.read(config_path)
    else:
        config = DefaultConfig

    for attr in config.get_config_attr():
        logger.info(f'{attr}: {getattr(config, attr)}')
    return config


def create_app(config):
    app = Flask(__name__, static_url_path='/')
    app.config['SECRET_KEY'] = config.SECRET_KEY

    jwt = JWTManager(app)

    db_path = os.path.join(config.DATASTORE, 'app_server.db')
    db = AppDB(db_path)

    app.register_blueprint(init_login(db), url_prefix='/login')

    @app.route('/')
    def home():
        return app.send_static_file('index.html')

    return app


if __name__ == '__main__':
    init_app_server()
