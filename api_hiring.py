from flask import Flask, request, abort, g, json, jsonify
from flask_restful import Resource, Api
from flask_restful import reqparse
from flask_cors import CORS
from functools import wraps
#from flaskext.mysql import MySQL
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as JWS
from flask_mail import Mail, Message
from hashlib import sha256
from random import Random
import email, smtplib, ssl
import requests
#import pymssql
import pymysql
#import sshtunnel
import decimal
from datetime import date
from datetime import datetime
import calendar
import random
import string
import time

#from pyblake2 import blake2b
# hazmat encrypted
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from decimal import Decimal


#MIME email HTML
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Generate Alphabet dan numerik
# -----------------------------
def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits
    result_str = ''.join((random.choice(letters_and_digits) for i in range(length)))
    return result_str

#load configurations
with open('./config/config-lokal.json', 'r') as f:
    #config is the json file
    #loaded up configurations to spec_names, specifications
    configuration = json.load(f)

#assign port number
portNumber = configuration["port"]
#assign hostname
hostName = configuration["host"]
DB_Server = configuration["DB_Server"]
DB_User = configuration["DB_User"]
DB_Password = configuration["DB_Password"]
DB_Name = configuration["DB_Name"]
Expired = configuration["Expired"]
API_prefix = configuration["API_prefix"]
API_key = configuration["API_key"]
#assign debug boolean
debugBoolean = configuration["debug"]

#assign mail server
MAIL_SERVER = configuration["MAIL_SERVER"]
MAIL_PORT = configuration["MAIL_PORT"]
MAIL_USERNAME = configuration["MAIL_USERNAME"]
MAIL_PASSWORD = configuration["MAIL_PASSWORD"]
MAIL_USE_TLS = configuration["MAIL_USE_TLS"]
MAIL_USE_SSL = configuration["MAIL_USE_SSL"]


app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})

########### SETTING EMAIL MESSAGES AND SMTP ###########
app.config['MAIL_SERVER'] = MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = MAIL_USE_TLS
app.config['MAIL_USE_SSL'] = MAIL_USE_SSL
mail = Mail(app)

app.config['SECRET_KEY'] = 'top secret!'
jws = JWS(app.config['SECRET_KEY'], expires_in=Expired)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)


api = Api(app, prefix=API_prefix)

#context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#context.load_cert_chain('server.crt', 'server.key')

SECRETKEY = b'pseudorandomly generated server secret key'
AUTH_SIZE = 16

key = 'DB7x0bKPrQWlv-Yq3GyeEMaA-IMFUToC8M6OmWgUImM='.encode()
f = Fernet(key)

def sign(cookie):
    h = blake2b(data=cookie, digest_size=AUTH_SIZE, key=SECRETKEY)
    return h.hexdigest()

def verify(cookie, sig):
    good_sig = sign(cookie)
    if len(sig) != len(good_sig):
        return False
    # Use constant-time comparison to avoid timing attacks.
    result = 0
    for x, y in zip(sig, good_sig):
        result |= ord(x) ^ ord(y)
    return result == 0

# The actual decorator function
def require_appkey(view_function):

    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        if request.args.get('key') and request.args.get('key') == API_key:
            return view_function(*args, **kwargs)
        else:
            abort(401)

    return decorated_function

users = {
    "john": generate_password_hash("travolta"),
    "susan": generate_password_hash("susanti")
}

for user in users.keys():
    token = jws.dumps({'username': user})
    print('*** token for {}: {}\n'.format(user, token))

@basic_auth.verify_password
def verify_password(username, password):
    g.user = None
    if username in users:
        if check_password_hash(users.get(username), password):
            g.user = username
            return True
    return False

@token_auth.verify_token
def verify_token(token):
    g.user = None
    try:
        data = jws.loads(token)
    except:  # noqa: E722
        return False
    if 'username' in data:
        g.user = data['username']
        return True
    return False
# Read Private Key and Public Key Hazmat
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
    key_file.read(),
    password=None,
    backend=default_backend()
    )

with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
    key_file.read(),
    backend=default_backend()
    )


## -------- Tabel Pengguna Login Akses Sistem
## ------------------------------------------
class CreatePengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('name', type=str, help='1. name')
            parser.add_argument('email', type=str, help='2. email')
            parser.add_argument('password', type=str, help='3. password')
            parser.add_argument('created', type=str, help='4. created')
            parser.add_argument('updated', type=str, help='5. updated')      
            args = parser.parse_args()

            _name = args['name']
            _email = args['email']
            _password = args['password']
            _created = args['created']
            _updated = args['updated']

            # message_paswd = _user_password.encode('UTF8')
            res_user_password = _password.encode()
            enc_paswd = f.encrypt(res_user_password)
            res_enc_password = enc_paswd.decode()

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_CreateUser', (_name, _email, res_enc_password, _created, _updated,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeletePengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')   
            args = parser.parse_args()

            _user_email = args['user_email']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_DeletePengguna', (_user_email,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus pengguna..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ReadPengguna(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try: 
            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_ReadUser')
            data = cursor.fetchall()
            conn2.close

            items_ReadPengguna = [];
            for item in data:
                i = {
                    'ID':item[0], 'name':item[1], 'email':item[2],
                    'password':item[3], 'created':item[4], 'user_kode':item[5]
                }

                items_ReadPengguna.append(i)

            return jsonify(items_ReadPengguna)

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class GetLogin(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')
            parser.add_argument('user_password', type=str, help='2. user_password')
            args = parser.parse_args()

            _user_email = args['user_email']
            _user_password = args['user_password']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_Login', (_user_email,))
            data = cursor.fetchall()
            conn2.close

            list_Pengguna = [];
            for list1 in data:
                ID = list1[0]
                name = list1[1]
                email = list1[2]
                password = list1[3]
                created = list1[4]
                updated = list1[5]

                key_password = password.encode()
                user_password = f.decrypt(key_password)
                dec_user_password = user_password.decode()

                i = {
                    'ID':ID,
                    'name':name,
                    'email':email,
                    'password':password,
                    'created':created,
                    'updated':updated,
                }
                
                list_Pengguna.append(i)

            if(len(data) > 0):
                if(dec_user_password == _user_password):
                    return jsonify({'StatusCode':'200', 'message':'Authentication success', 'data':list_Pengguna})
                else:
                    return jsonify({'StatusCode':'100', 'message':'Authentication Failed...!'})
            else:
                    return jsonify({'StatusCode':'100', 'message':'Authentication Failed...!'})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': str(e)})


class ResetPassword(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='Email to create user')
            parser.add_argument('user_password', type=str, help='Password to create user')
            args = parser.parse_args()

            _user_email = args['user_email']
            _user_password = args['user_password']

            # message_paswd = _user_password.encode('UTF8')
            _user_password = _user_password.encode()
            enc_paswd = f.encrypt(_user_password)
            enc_password = enc_paswd.decode()

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_ResetPassword', (_user_email, enc_password,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return {'StatusCode':'200', 'Message': 'Reset Password success'}
            else:
                return {'StatusCode':'100', 'Message': str(data[0])}

        except Exception as e:
            return {'error': str(e)}


## -------- Tabel Session -------------------
## ------------------------------------------
class CreateSession(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def post(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('userID', type=str, help='1. userID')
            parser.add_argument('name', type=str, help='2. name')
            parser.add_argument('description', type=str, help='3. description')
            parser.add_argument('start', type=str, help='4. start')
            parser.add_argument('duration', type=str, help='5. duration')
            parser.add_argument('created', type=str, help='6. created')
            parser.add_argument('updated', type=str, help='7. updated')      
            args = parser.parse_args()

            _userID = args['userID']
            _name = args['name']
            _description = args['description']
            _start = args['start']
            _duration = args['duration']
            _created = args['created']
            _updated = args['updated']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_CreateSession', (_userID, _name, _description, _start, _duration, _created, _updated,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class DeleteSession(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def delete(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('user_email', type=str, help='1. user_email')   
            args = parser.parse_args()

            _user_email = args['user_email']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_DeletePengguna', (_user_email,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return jsonify({'StatusCode':'200', 'message': 'Sukses hapus pengguna..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


class ListSession(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('nama_user', type=str, help='1. nama_user')   
            args = parser.parse_args()

            _nama_user = args['nama_user']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_ListSession', (_nama_user,))
            data = cursor.fetchall()
            conn2.close

            items_ReadSession = [];
            for item in data:
                i = {
                    'ID':item[0], 'userID':item[1], 'nama_user':item[2], 'name':item[3], 'description':item[4], 
                    'start':item[5], 'duration':item[6], 'created':item[7], 'updated':item[8]
                }

                items_ReadSession.append(i)

            return jsonify({'StatusCode':'200', 'data':items_ReadSession})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': 'Nama tidak ditemukan..!'})


class DetilSession(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def get(self):
        try:
            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_DetilSession')
            data = cursor.fetchall()
            conn2.close

            items_ReadSession = [];
            for item in data:
                i = {
                    'ID':item[0], 'userID':item[1], 'nama_user':item[2], 'name':item[3], 'description':item[4], 
                    'start':item[5], 'duration':item[6], 'created':item[7], 'updated':item[8]
                }

                items_ReadSession.append(i)

            return jsonify({'StatusCode':'200', 'data':items_ReadSession})

        except Exception as e:
            return jsonify({'StatusCode':'100', 'Message': 'Nama tidak ditemukan..!'})


class UpdateSession(Resource):
    
    @require_appkey
    @multi_auth.login_required
    def put(self):
        try:
            # Parse the arguments
            parser = reqparse.RequestParser()
            parser.add_argument('ID', type=str, help='1. ID')
            parser.add_argument('userID', type=str, help='2. userID')
            parser.add_argument('name', type=str, help='3. name')
            parser.add_argument('description', type=str, help='4. description')
            parser.add_argument('start', type=str, help='5. start')
            parser.add_argument('duration', type=str, help='6. duration')
            parser.add_argument('created', type=str, help='7. created')
            parser.add_argument('updated', type=str, help='8. updated')      
            args = parser.parse_args()

            _ID = args['ID']
            _userID = args['userID']
            _name = args['name']
            _description = args['description']
            _start = args['start']
            _duration = args['duration']
            _created = args['created']
            _updated = args['updated']

            conn2 = pymysql.connect(host=DB_Server, user=DB_User, password=DB_Password, database=DB_Name)
            cursor = conn2.cursor()
            cursor.callproc('sp_UpdateSession', (_ID, _userID, _name, _description, _start, _duration, _created, _updated,))
            data = cursor.fetchall()

            if len(data) == 0:
                conn2.commit()
                conn2.close
                return jsonify({'StatusCode':'200', 'message': 'Sukses simpan..!'})
            else:
                return jsonify({'StatusCode':'100', 'message': str(data[0])})

        except Exception as e:
            return {'error': str(e)}


## --- API Pengguna Aplikasi Web ----

### ---- Login USER ---
api.add_resource(CreatePengguna, '/CreatePengguna')
api.add_resource(DeletePengguna, '/DeletePengguna')
api.add_resource(ReadPengguna, '/ReadPengguna')
api.add_resource(GetLogin, '/GetLogin')
api.add_resource(ResetPassword, '/ResetPassword')
### ---- Login USER ---

### ---- Session --------
api.add_resource(CreateSession,'/CreateSession')
api.add_resource(DeleteSession,'/DeleteSession')
api.add_resource(ListSession,'/ListSession')
api.add_resource(DetilSession,'/DetilSession')
api.add_resource(UpdateSession,'/UpdateSession')

## --- Running SERVER API --- ##
## -------------------------- ##
if __name__ == '__main__':
    app.run(host=hostName, port=portNumber, debug=debugBoolean)
