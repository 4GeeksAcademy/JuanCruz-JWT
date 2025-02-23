"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required




api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route("/signup", methods = ["POST"])
def signup() :
    response_body = {}
    data = request.json
    user = User(email = data['email'].lower(),
                password = data['password'],
                is_active = True)
    db.session.add(user)
    db.session.commit()
    response_body['message'] = "Usuario creado exitosamente!"
    return response_body,200


@api.route("/login", methods = ["POST"])
def signin() :
    response_body = {}
    email = reques.json.get("email",None)
    password = reques.json.get("password",None)
    user = db.session.execute(db.select(User).where(User.email == email)).scalar()
    if user and password == user.password:
        access_token = create_access_token(identity=[user.username, user.email, user.avatar_url])
        response_body['access_token'] = access_token
        response_body['message'] = "Login exitoso!"
        response_body['results'] = user.serialize()
        return response_body, 200
    else:
        response_body['message'] = "Error, pasword o email incorrectos"
    return response_body



@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200
