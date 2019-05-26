import peeweedbevolve
from flask import Flask, render_template, request, redirect, url_for, jsonify
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_login import current_user, login_user, LoginManager, UserMixin, logout_user
from authlib.flask.client import OAuth
import os
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
import braintree
from flask_cors import CORS


app = Flask(__name__)



cors = CORS(app, resources={r"/*": {"origins": "*"}})

app.secret_key=b'\xd4\xd2\xbc.8~\x88;\x11\x90W\x9e\x05#\xe8\xed\x1bi\xa0zW\xad\x16\x9c'

jwt = JWTManager(app)

login_manager = LoginManager()
login_manager.init_app(app)

gateway = braintree.BraintreeGateway(
    braintree.Configuration(
        braintree.Environment.Sandbox,
        merchant_id="nj3d7cgfdjw5686p",
        public_key="xtmdm49xh6vynmdr",
        private_key="ba50833c251a76b0dc00bbe808b09e4f"
    )
)


@app.route("/client_token", methods=["GET"])
def client_token():
    client_token = gateway.client_token.generate()
    return jsonify({"client_token" : client_token})

@app.route("/get_nonce", methods=["POST"])
@jwt_required
def get_nonce():
    current_user_id = get_jwt_identity()
    user = current_user_id
    amount= request.json.get("amount")
    nonce = request.json.get("nonce")
    result = gateway.transaction.sale({
    "amount": amount,
    "payment_method_nonce": nonce,
    "options": {
    "submit_for_settlement": True
    }

})

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

@app.cli.command() # new
def migrate(): # new 
    db.evolve(ignore_tables={'base_model'}) # new

@login_manager.user_loader
def load_user(user_id):
    return User.get(User.id == user_id)


@app.route("/login", methods=['GET', 'POST'])
def login():
    email = request.json.get("email")
    password = request.json.get("password")
    user = User.get_or_none(User.email == email)
    if user and check_password_hash(user.password, password):
        login_user(user)
        return jsonify({
            "access_token": create_access_token(identity=user.id),
            "message": "Successfully created a user and signed in.",
            "status": "success",
            "user": {
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "email or password incorrect" })


@app.route("/userprofile")
@jwt_required
def userprofile():
    current_user_id = get_jwt_identity()
    user = User.get_or_none(User.id == current_user_id)
    return jsonify({
                    "user": {
                            "name": user.name,
                            "email": user.email,        
                            "id": user.id
                            }})


@app.route("/create", methods= ["POST"])
def create():
    name = request.json.get("name")
    email = request.json.get("email")
    password = request.json.get("password")
    valid_email = not User.select().where(User.email == email).exists()
    valid_password = len(password) <= 6
    hashed_password = generate_password_hash(password)
    if valid_email and valid_password:
        user = User(name= name, email= email,password=hashed_password)
        user.save()
        return jsonify({
            "access_token": create_access_token(identity=user.id),
            "message": "Successfully created a user.",
            "status": "success",
            "user": {
                "name": user.name,
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "fail" })



@app.route('/update', methods=['POST', 'GET'])
@jwt_required
def update():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    email = request.json.get("email")
    name = request.json.get("name")
    password = request.json.get("password")
    valid_password = len(password) >= 6
    hashed_password = generate_password_hash(password)
    user.email = email
    user.name = name
    user.password = hashed_password
    if user.save():
        return jsonify({
            "message": "Successfully updated.",
            "status": "success",
            "user": {
                "name": user.name,
                "email": user.email,
                "password": user.password
                }
            })
    else:
        return jsonify ({ "msg" : "fail" })


@app.route('/delete_user', methods=['POST'])
@jwt_required
def delete_user():
    current_user_id = get_jwt_identity()
    user = User.get_by_id(current_user_id)
    logout_user()
    if user.delete_instance():
        return jsonify ({"msg": "success"})
    else:
        return jsonify ({"msg": "fail"})



if __name__ == '__main__':
    app.run()

