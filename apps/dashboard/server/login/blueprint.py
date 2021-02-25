import functools
import logging

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash

from apps.dashboard.server.database.db import AppDB

logger = logging.getLogger('AppServerLogin')


def admin_required(func):
    """Make sure user is admin before proceeding with request"""
    @functools.wraps(func)
    def wrapper_admin_required(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user != 'admin':
            return jsonify(message='User is not admin'), 500
        return func(*args, **kwargs)
    return wrapper_admin_required


def init_login(db: AppDB):
    blueprint = Blueprint('login', __name__)
    users = db.users

    @blueprint.route('/', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        current_user = users.get_user(username)

        if not current_user:
            return jsonify({'message': f'User {username} does not exist'}), 500

        if check_password_hash(current_user['password'], password):
            access_token = create_access_token(identity=username)
            return jsonify({
                'message': 'Logged in as {}'.format(current_user['username']),
                'access_token': access_token,
            })
        else:
            return jsonify({'message': 'Wrong credentials'})

    @blueprint.route("/admin")
    @jwt_required()
    @admin_required
    def admin():
        return jsonify(status="successful"), 200

    return blueprint
