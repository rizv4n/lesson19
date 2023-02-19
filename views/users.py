import hashlib

from flask import request
from flask_restx import Resource, Namespace

from models import User, UserSchema
from setup_db import db

user_ns = Namespace('users')


def get_hash(password):
    return hashlib.md5(password.encode('utf-8')).hexdigest()


@user_ns.route('/')
class UsersView(Resource):
    def get(self):
        t = db.session.query(User)
        all_users = t.all()
        res = UserSchema(many=True).dump(all_users)
        return res, 200

    def post(self):
        req_json = request.json
        req_json["password"] = get_hash(req_json["password"])
        ent = User(**req_json)
        db.session.add(ent)
        db.session.commit()
        return "", 201, {"location": f"/users/{ent.id}"}


@user_ns.route('/<int:bid>')
class MovieView(Resource):
    def get(self, uid):
        b = db.session.query(User).get(uid)
        sm_d = UserSchema().dump(b)
        return sm_d, 200

    def put(self, uid):
        user = db.session.query(User).get(uid)
        req_json = request.json
        user.role = req_json.get("role")
        user.username = req_json.get("username")
        user.password = req_json.get("password")
        db.session.add(user)
        db.session.commit()
        return "", 204

    def delete(self, uid):
        user = db.session.query(User).get(uid)

        db.session.delete(user)
        db.session.commit()
        return "", 204
