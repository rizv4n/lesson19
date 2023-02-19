import calendar
import hashlib
import datetime
import jwt

from flask import request, abort
from flask_restx import Resource, Namespace

from models import User, UserSchema
from setup_db import db


JWT_SECRET = 'HnKmUy12Iu88.'
JWT_ALGORITHM = 'HS256'


auth_ns = Namespace('auth')


def auth_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]
        try:
            jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)
        except Exception as e:
            print("JWT Decode Exception", e)
            abort(401)
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'role' not in request.headers:
            abort(401)
        data = request.headers['role']
        if data == 'admin':
            return func(*args, **kwargs)
        else:
            print("You're not Admin!")
            abort(401)
    return wrapper


def get_by_username(username):
    t = db.session.query(User).filter(User.username == username)
    users = t.first()
    return UserSchema(many=False).dump(users)


def compare_password(password_hash, password):
    generate_hash = hashlib.md5(password.encode('utf-8')).hexdigest()
    return password_hash == generate_hash


def generate_tokens(username, password, is_refresh=False):
    user = get_by_username(username)

    if user is None:
        abort(404)

    if not is_refresh:
        if not compare_password(user['password'], password):
            abort(400)

    data = {
        "username": user['username'],
        "role": user['role']
    }

    min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    data["exp"] = calendar.timegm(min30.timetuple())
    access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

    days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
    data["exp"] = calendar.timegm(days130.timetuple())
    refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


def approve_refresh_token(refresh_token):
    data = jwt.decode(jwt=refresh_token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])
    username = data.get("username")

    return generate_tokens(username, None, is_refresh=True)


@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        data = request.json

        username = data.get("username")
        password = data.get("password")

        return generate_tokens(username, password)

    def put(self):
        data = request.json
        token = data.get("refresh_token")

        tokens = approve_refresh_token(token)

        return tokens, 201

