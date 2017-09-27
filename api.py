import os
from datetime import datetime
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyrsis3'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

#User table
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    phone = db.Column(db.String(32))
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

#Money table
class Money(db.Model):
    __tablename__ = 'Money'
    id = db.Column(db.Integer,primary_key=True)
    user_id = db.Column(db.Integer)
    money_value = db.Column(db.Integer)
    date_time = db.Column(db.DateTime)

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    print ("Password Verification called")
    print("User Name or Token=",username_or_token)
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

#create new users
@app.route('/api/users', methods=['POST'])
def new_user():
    #print (request.data)
    #username = request.args.get('username')
    #password = request.args.get('password')
    #name = request.args.get('name')
    #phone = request.args.get('phone')
    username = request.json.get('username')
    password = request.json.get('password')
    name = request.json.get('name')
    phone = request.json.get('phone')
    print ("User Registration Request Received")
    print (username)
    print (password)
    if username is None or password is None:
        return jsonify({'status': 'failure' , 'code': 400,})
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'status': 'failure' , 'code': 400,})
        abort(400)    # existing user
    user = User(username=username,name=name,phone=phone)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'status': 'success' , 'code': 200,}))

#display table information
@app.route('/generate_table')
def generate_table():
    rows_user = User.query.count()
    rows_money = Money.query.count()
    data_user = []
    data_money = []
    for i in range(0,rows_user+1):
        try:
            data_info = (User.query.filter_by(id=i).first().username)
            data_info_name = User.query.filter_by(id=i).first().name
            data_info_phone = User.query.filter_by(id=i).first().phone
            data_user.append({'userid' : i, 'username' : data_info, 'name': data_info_name, 'phone':data_info_phone})
        except:
            continue

    for i in range(0,rows_money+1):
        try:
            data_info_id = (Money.query.filter_by(id=i).first().user_id)
            data_info_money = (Money.query.filter_by(id=i).first().money_value)
            data_info_name = (User.query.filter_by(id = data_info_id).first().username)
            date_time_stamp = (Money.query.filter_by(id=i).first().date_time)
            data_money.append({'username': data_info_name,'money_deposited' : data_info_money,'date_time': date_time_stamp})
        except:
            continue
    return jsonify({'money_data':data_money,'user_data': data_user})

#main screen
@app.route('/')
def home():
    return ("API under development.")

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@app.route('/api/add_money/<int:money>')
@auth.login_required
def add_money(money):
    id = User.query.filter_by(username = g.user.username).first().id
    data = Money(user_id=id, money_value = money,date_time = datetime.now())
    db.session.add(data)
    db.session.commit()
    print("Money deposited by %d value %d is successful",(id,money))
    return (jsonify({'status': 'success' , 'code': 200,}))


if __name__ == '__main__':
    db.create_all()
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True,host='0.0.0.0',port=3000)