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
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt




api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route("/signup", methods = ["POST"])
def signup() :
    ata = request.get_json()

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "El correo electrónico ya está en uso"}), 400
    
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(
        name=data['name'],
        email=data['email'],
        password=hashed_password
        )
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuario creado exitosamente"}), 201

@api.route("/login", methods = ["POST"])
def login() :
    rdata = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        print(access_token)
        return jsonify({"message": "Inicio de sesión exitoso","access_token": access_token, "user": user.serialize()}), 200
    else:
        return jsonify({"message": "Error , Email o contraseña incorrectos"}), 401


@api.route("/private/<string:profile>", methods=["GET"])
def profile_user(profile):
    response_body = {}
    user = db.session.execute(db.select(User).filter(User.username.ilike(profile))).scalar() 
    if user:
        response_body['message'] = "Usuario encontrado"
        response_body['results'] = user.serialize()
        return response_body, 200
    else:
        response_body['message'] = "User no encontrado"
        response_body['results'] = {}
    return response_body, 404


@api.route('/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "Usuario no encontrado"}), 404
    
    db.session.delete(user)
    db.session.commit()

# @api.route("/private/check", methods=["GET"])
# @jwt_required()
# def profile_check():
#     response_body = {}
#     current_user = get_jwt_identity()
#     response_body['message'] = f'El usuario es: {current_user[0]}'
#     response_body['results'] = current_user[0]
#     return response_body, 200    



@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200
