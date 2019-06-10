import cherrypy
import authorised_access
import nacl.encoding
import nacl.signing
import nacl.pwhash
import nacl.utils
import nacl.secret
from nacl.public import SealedBox
import urllib.request
import json
import base64
import sqlite3
import time
import string
import socket
from jinja2 import Environment, FileSystemLoader

class ApiApp(object):
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on': 'True',
                  }

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        cherrypy.response.status = 404

        response = {
            "response": "404 page not found"
        }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        print("------------------------broadcats recieved-----------------")
        recieved_json = cherrypy.request.json
        error = 0

        print(recieved_json)
        if recieved_json['loginserver_record'] is None:
            error = 1
        elif recieved_json['message'] is None:
            error = 1
        elif recieved_json['sender_created_at'] is None:
            error = 1
        elif recieved_json['signature'] is None:
            error = 1

        if(recieved_json['message'] == " ")or(recieved_json['message'] == ""):
            error = 1

        conn = sqlite3.connect('webapp')
        c = conn.cursor()

        data = (recieved_json['loginserver_record'][:7], recieved_json['message'].replace("<", "&lt;").replace(">", "&gt;"),
                recieved_json['sender_created_at'], recieved_json['signature'],recieved_json['loginserver_record'])
        c.execute('INSERT INTO broadcasts VALUES (?,?,?,?,?)', data)

        conn.commit()
        conn.close()

        if error == 0:
            response = 'ok'
        else:
            response = 'error'

        response = {
            "response": response
        }
        print(response)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_privatemessage(self):
        print("-------------------private message recieved-------------------")
        recieved_json = cherrypy.request.json
        error = 0

        print(recieved_json)
        if recieved_json['loginserver_record'] is None:
            error = 1
        elif recieved_json['target_pubkey'] is None:
            error = 1
        elif recieved_json['target_username'] is None:
            error = 1
        elif recieved_json['encrypted_message'] is None:
            error = 1
        elif recieved_json['sender_created_at'] is None:
            error = 1
        elif recieved_json['signature'] is None:
            error = 1

        if (recieved_json['encrypted_message'] == " ") or (recieved_json['encrypted_message'] == ""):
            error = 1

        conn = sqlite3.connect('webapp')
        c = conn.cursor()

        data = (
        recieved_json['loginserver_record'],recieved_json['target_pubkey'],recieved_json['target_username'],
        recieved_json['encrypted_message'],recieved_json['sender_created_at'], recieved_json['signature'])
        c.execute('INSERT INTO private_messages VALUES (?,?,?,?,?,?)', data)

        conn.commit()
        conn.close()

        if error == 0:
            response = 'ok'
        else:
            response = 'error'

        response = {
            "response": response
        }
        print(response)
        return response

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def ping_check(self):
        current_time = time.time()
        error_message = "0"

        try:
            JSON = cherrypy.request.json
            print("------------------recieved json in ping check---------------------")

            try:
                connection_address = JSON['connection_address']
            except:
                error_message = "missing connection_address"

            try:
                connection_location = str(JSON['connection_location'])
                if (connection_location == "0") or (connection_location == "1") or (connection_location == "2"):
                    error_message = "0"
                else:
                    error_message = "connection_location must be a 0,1 or 2"
            except:
                error_message = "missing connection_location"
        except:
            error_message = "expected json type"

        if error_message == "0":
            response = {
                "response": "ok",
                "my_time": str(current_time)
            }
        else:
            response = {
                "response": "error",
                "message": error_message,
                "my_time": str(current_time)
            }
        print(response)
        return response


env = Environment(loader=FileSystemLoader('templates'))

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/templates/example.css' /></head><body>"


class MainApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        tmpl = env.get_template('404.html')
        cherrypy.response.status = 404
        try:
            return tmpl.render(user=cherrypy.session['username'])
        except KeyError:  # There is no username
            return tmpl.render()

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        tmpl = env.get_template('index.html')
        #return tmpl.render(user='Login')
        raise cherrypy.HTTPRedirect('/login')
     #test
    # @cherrypy.expose
    # def home(self):
    #     tmpl = env.get_template('home.html')
    #     print("homee")
    #     refresh()
    #
    #     return tmpl.render(user_status=status, user=cherrypy.session['username'], users_online=cherrypy.session['users_online'][0] ,status = cherrypy.session['users_online'][1])
    #
    @cherrypy.expose
    def login(self, bad_attempt = 0):
        test = env.get_template('login.html')
        attempt = ""

        if bad_attempt != 0:
            attempt = "Invalid username/password!"

        return test.render(error=attempt,user='Login')

    @cherrypy.expose
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        conn = sqlite3.connect('webapp')
        c = conn.cursor()
        if(username!= None)and(password != None):
            """Check their name and password and send them either to the main page, or back to the main login screen."""
            error = authoriseUserLogin(username, password)
            if error == 0:
                cherrypy.session['username'] = username
                cherrypy.session['password'] = password
                cherrypy.session['privatedata'] = get_privatedata()
                cherrypy.session['blocked_broadcast']= []
                cherrypy.session['status'] = 'online'
                cherrypy.session['count'] = 0
                if cherrypy.session['privatedata']['response'] == "ok":
                    raise cherrypy.HTTPRedirect('/privatedata_password2')
                else:
                    c.execute('SELECT * FROM user_data WHERE username=(?)', [cherrypy.session['username'], ])
                    data = c.fetchone()
                    if data == None:
                        new_pubkey()
                        print(cherrypy.session['signing_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
                        user = (cherrypy.session['username'], cherrypy.session['password'], cherrypy.session['pub_key'], cherrypy.session['signing_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'))
                        c.execute('INSERT INTO user_data VALUES (?,?,?,?)', user)
                    else:
                        c.execute('SELECT private_key FROM user_data WHERE username=(?)', [cherrypy.session['username'], ])
                        cherrypy.session['signing_key'] = nacl.signing.SigningKey(str(c.fetchone())[2:66],encoder=nacl.encoding.HexEncoder)
                        verify_key_hex = cherrypy.session['signing_key'].verify_key.encode(encoder=nacl.encoding.HexEncoder)
                        cherrypy.session['pub_key'] = verify_key_hex.decode('utf-8')
                        get_loginserver_record()

                    conn.commit()
                    conn.close()
                    ping()
                    report()
                    #ping()
                    list_users()
                    get_loginserver_record()
                raise cherrypy.HTTPRedirect('/posts?status=online')
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def list_apis(self):
        url = "http://cs302.kiwi.land/api/list_apis"
        list_users()
        payload = {}

        send(url, payload,5)

    @cherrypy.expose
    def posts(self, status = 'online'):
        try:
            tmpl = env.get_template('posts.html')

            if(cherrypy.session['status'] != status):
                print(status)
                print(cherrypy.session['status'])
                cherrypy.session['status'] = status
            if(cherrypy.session['count']<= 3):
               cherrypy.session['count'] += 1
            else:
               cherrypy.session['count'] = 0
        
            refresh(cherrypy.session['count'])
       
            print(cherrypy.session['status'])
            return tmpl.render(user_status=cherrypy.session['status'], user=cherrypy.session['username'],
                users_online=cherrypy.session['users_online'][0], status=cherrypy.session['users_online'][1], post=read_posts(),
                           posts_blocking=cherrypy.session['posts_blocking'],current_url=("posts"),refresh =1)
        except:
            raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def post_message(self, message='0',key='0'):

        if (message != '0'):
            s = key.replace('[', '')
            s = s.replace(']', '')
            cherrypy.session['blocked_broadcast'].append(s)

            send_broadcast(message)

        raise cherrypy.HTTPRedirect('/posts'+cherrypy.session['status'])

    @cherrypy.expose
    def private_messages(self, status='online',person=0):
        tmpl = env.get_template('messages.html')
        cherrypy.session['person'] = person
        cherrypy.session['status'] = status
        if(cherrypy.session['count']<= 3):
            cherrypy.session['count'] += 1
        else:
            cherrypy.session['count'] = 0
        
        refresh(cherrypy.session['count'])
        return tmpl.render(user_status=cherrypy.session['status'], user=cherrypy.session['username'],
                           users_online=cherrypy.session['users_online'][0], status=cherrypy.session['users_online'][1],
                           post=read_private_messages(),posts_blocking=cherrypy.session['private_posts_blocking'],
                           current_url=("private_messages"),person=cherrypy.session['users_online'][0][int(person)],refresh =1)

    @cherrypy.expose
    def post_private_message(self, message='0',status='online'):
        if (message != '0'):
            send_privatemessage(cherrypy.session['users_online'][2][int(cherrypy.session['person'])],cherrypy.session['users_online'][0][int(cherrypy.session['person'])],message)           

        raise cherrypy.HTTPRedirect('/private_messages?status='+cherrypy.session['status']+"&person="+cherrypy.session['person'])

    @cherrypy.expose
    def search_broadcasts(self, find='0'):
        if (find != '0'):
            search_db(find)

        raise cherrypy.HTTPRedirect('/found')

    @cherrypy.expose
    def found(self):
        tmpl = env.get_template('found.html')

        refresh()
        return tmpl.render(user_status=cherrypy.session['status'], user=cherrypy.session['username'],
                           users_online=cherrypy.session['users_online'][0], status=cherrypy.session['users_online'][1],
                           post= cherrypy.session['found_post'])

    @cherrypy.expose
    def privatedata_password(self, bad_attempt = 0):
        tmpl = env.get_template('privatedata_password.html')
        attempt = ""
        if bad_attempt != 0:
            attempt = "Invalid username/password!"

        return tmpl.render(error=attempt, user='Login')

    @cherrypy.expose
    def private_data_upload(self, private_data_password=None):
        if(private_data_password is None):
            raise cherrypy.HTTPRedirect('/privatedata_password?bad_attempt=1')
        else:
            add_privatedata(encrypt_private_data(create_secret_box(private_data_password)))

        raise cherrypy.HTTPRedirect('/posts')

    @cherrypy.expose
    def privatedata_password2(self, bad_attempt=0):
        tmpl = env.get_template('privatedata_password2.html')

        attempt = ""
        if bad_attempt != 0:
            attempt = "Invalid username/password!"

        return tmpl.render(error=attempt, user='Login')

    @cherrypy.expose
    def private_data_decode(self, private_data_password=None):
        cherrypy.session['loginserver_pubkey'] = get_lgoinserver_pubkey()
        if (private_data_password is None):
            raise cherrypy.HTTPRedirect('/privatedata_password2?bad_attempt=1')
        else:
            # try:
            decrypt_private_data(create_secret_box(private_data_password), cherrypy.session['privatedata'])
            report()
            #ping()
            list_users()
            get_loginserver_record()
            # except:
            #     raise cherrypy.HTTPRedirect('/privatedata_password2?bad_attempt=1')
        raise cherrypy.HTTPRedirect('/posts')


# Functions only after here
def send(url, payload,time_out):
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey':cherrypy.session['apikey'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    s = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=s, headers=headers)
        response = urllib.request.urlopen(req,timeout=time_out)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
    except urllib.error.URLError as error:
        if isinstance(error.reason, socket.timeout):
            print("socket timed out - url %s",url)
        else:
            print("some other error happend")
    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)
    return JSON_object


def sign(message):
    message_bytes = bytes(message, encoding='utf-8')
    signed = cherrypy.session['signing_key'].sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    return signed.signature.decode('utf-8')


def authoriseUserLogin(username, password):
    print("Log on attempt from {0}:{1}".format(username, password))

    if get_apikey(username, password) == 'ok':
        print("Success")
        return 0
    else:
        print("Failure")
        return 1


def report():
    url = "http://cs302.kiwi.land/api/report"
    print(str(socket.gethostbyname(socket.getfqdn())))
    local_ip = str(socket.gethostbyname(socket.getfqdn())) +":10000"
    payload = {
        "connection_address": local_ip,
        "connection_location": "2",
        "incoming_pubkey": cherrypy.session.get('pub_key'),
        "status": cherrypy.session['status']
    }

    send(url, payload,5)


def ping():
    url = "http://cs302.kiwi.land/api/ping"

    payload = {
        "pubkey": cherrypy.session['pub_key'],
        "signature": sign(cherrypy.session['pub_key']),
    }

    send(url, payload,5)


def new_pubkey():
    url = "http://cs302.kiwi.land/api/add_pubkey"

    cherrypy.session['signing_key'] = nacl.signing.SigningKey.generate()
    verify_key_hex = cherrypy.session['signing_key'].verify_key.encode(encoder=nacl.encoding.HexEncoder)
    cherrypy.session['pub_key'] = verify_key_hex.decode('utf-8')

    payload = {
        "pubkey": cherrypy.session.get('pub_key'),
        "username": cherrypy.session.get('username'),
        "signature": sign(cherrypy.session.get('pub_key') + cherrypy.session.get('username')),
    }

    cherrypy.session['loginserver_record'] = send(url, payload,5)['loginserver_record']


def list_users():
    url = "http://cs302.kiwi.land/api/list_users"

    payload = {
    }

    users = [[],[],[],[],[]]

    response = send(url, payload,5)
    conn = sqlite3.connect('webapp')
    c = conn.cursor()
    c.execute("DELETE FROM network_user_data")

    for i in response['users']:
        if(i['username'] != 'sbud159'):
            users[0].append(i['username'])
            users[1].append(i['status'])
            users[2].append(i['incoming_pubkey'])
            users[3].append(i['connection_address'])


            data = (
            i['username'], i['incoming_pubkey'])
            c.execute('INSERT INTO network_user_data VALUES (?,?)', data)

    conn.commit()
    conn.close()

    cherrypy.session['users_online'] = users


def get_apikey(username,password):
    url = "http://cs302.kiwi.land/api/load_new_apikey"

    payload = {
    }

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    s = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=s, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    cherrypy.session['apikey'] = JSON_object['api_key']

    return JSON_object['response']


def send_broadcast(message):
    current_time = str(time.time())
    url = "http://" + str(socket.gethostbyname(socket.getfqdn())) + ":10000/api/rx_broadcast"
    payload = {
        "loginserver_record": cherrypy.session.get('loginserver_record'),
        "message": message,
        "sender_created_at": current_time,
        "signature": sign(cherrypy.session.get('loginserver_record') + message + current_time)
    }
    send(url, payload,0.5)
    print(message)
    for i in range(len(cherrypy.session['users_online'][3])):
        try:
            url = "http://"+cherrypy.session['users_online'][3][i] +"/api/rx_broadcast"
            payload = {
                "loginserver_record": cherrypy.session.get('loginserver_record'),
                "message": message,
                "sender_created_at": current_time,
                "signature": sign(cherrypy.session.get('loginserver_record') + message + current_time)
            }
            send(url, payload)
            print("yay " + cherrypy.session['users_online'][0][i] +" "+ cherrypy.session['users_online'][3][i])
        except:
            print("rip "+ cherrypy.session['users_online'][0][i] + " "+ cherrypy.session['users_online'][3][i])

def send_privatemessage(target_pubkey,target_username,message):
    encryped =create_sealedbox(cherrypy.session['pub_key'],message)
    current_time = str(time.time())
    url = "http://" + str(socket.gethostbyname(socket.getfqdn())) + ":10000/api/rx_privatemessage"
    payload = {
            "loginserver_record": cherrypy.session.get('loginserver_record'),
            "target_pubkey": cherrypy.session['pub_key'],
            "target_username": target_username,
            "encrypted_message": encryped,
            "sender_created_at": current_time,
            "signature": sign(cherrypy.session.get('loginserver_record')+target_pubkey+target_username+encryped+current_time)
    }

    send(url, payload,0.5)

    encryped =create_sealedbox(target_pubkey,message)
    url = "http://" + str(socket.gethostbyname(socket.getfqdn())) + ":10000/api/rx_privatemessage"
    payload = {
            "loginserver_record": cherrypy.session.get('loginserver_record'),
            "target_pubkey": target_pubkey,
            "target_username": target_username,
            "encrypted_message": encryped,
            "sender_created_at": current_time,
            "signature": sign(cherrypy.session.get('loginserver_record')+target_pubkey+target_username+encryped+current_time)
    }

    send(url, payload,0.5)

    for i in range(len(cherrypy.session['users_online'][3])):
        url = "http://"+cherrypy.session['users_online'][3][i]+"/api/rx_privatemessage"
        payload = {
            "loginserver_record": cherrypy.session.get('loginserver_record'),
            "target_pubkey": target_pubkey,
            "target_username": target_username,
            "encrypted_message": encryped,
            "sender_created_at": current_time,
            "signature": sign(cherrypy.session.get('loginserver_record')+target_pubkey+target_username+encryped+current_time)
        }
        try:
            send(url, payload,0.5)
            print("yay private message sent to "+ cherrypy.session['users_online'][0][i])
        except:
            print(cherrypy.session['users_online'][0][i] + "does not have private_message")

def create_sealedbox(target_pubkey,message):

    verifykey = nacl.signing.VerifyKey(target_pubkey.encode('utf-8'), encoder=nacl.encoding.HexEncoder)
    pubkey = verifykey.to_curve25519_public_key()
    sealed_box = nacl.public.SealedBox(pubkey)
    message_bytes = bytes(message, 'utf-8')
    encrypted = sealed_box.encrypt(message_bytes,encoder=nacl.encoding.HexEncoder)

    return encrypted.decode('utf-8')


def check_messages(ip):

    url = "http://" + ip + "/api/checkmessages"

    conn = sqlite3.connect('webapp')
    c = conn.cursor()

    payload = {
        'since': cherrypy.session['time_last_online']
    }

    response = send(url, payload,0.5)
    for i in response['broadcast']:
        broadcast = (i['loginseerver_record'], i['message'], i['sender_created_at'],i['signature'])
        c.execute('INSERT INTO broadcasts VALUES (?,?,?,?)', broadcast)

    conn.commit()
    conn.close()


def check_pubkey(users_pubkey):
    url = "http://cs302.kiwi.land/api/check_pubkey"

    payload = {
        "pubkey": users_pubkey,
    }

    return send(url, payload,5)

def get_lgoinserver_pubkey():
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"

    payload = {
    }

    return send(url, payload,5)['pubkey']

def refresh(count):
    
    
    if(count==3):

        print('--------------------------refreshing-----------------------------')
       
        report()
      
        #ping()
        list_users()
        get_loginserver_record()
        print('--------------------------health check-----------------------------')
        for i in range(len(cherrypy.session['users_online'][3])):
            try:
                ping_check(cherrypy.session['users_online'][3][i])
                print("yay " + cherrypy.session['users_online'][0][i] + " " + cherrypy.session['users_online'][3][i])
            except:
                print("rip "+ cherrypy.session['users_online'][0][i] +cherrypy.session['users_online'][3][i])
    

    #send_privatemessage('0252660c6d8899959d2d10a53000e0526353b9d93d3c944f47ef9d20e05e3a58', 'ewon466', 'test')

    #send_privatemessage('dc60319e65f667f0813ca5f561423d09f6c5e0bf4b3a2a720f9e37935d899094','jchu491','hello')


def add_privatedata(privatedata):
    url = "http://cs302.kiwi.land/api/add_privatedata"
    current_time = str(time.time())

    payload = {
        "privatedata": privatedata,
        "loginserver_record": cherrypy.session.get('loginserver_record'),
        "client_saved_at": current_time,
        "signature": sign(privatedata + cherrypy.session.get('loginserver_record') + current_time)
    }

    send(url, payload,5)


def get_privatedata():
    url = "http://cs302.kiwi.land/api/get_privatedata"

    payload = {
    }

    return send(url, payload,5)


def create_secret_box(password):
    salt = ""
    for i in range(16):
        salt += password

    b = bytes(salt, 'utf-8')
    password_bytes = bytes(password, 'utf-8')
    salt_bytes = b[:16]
    ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE

    key=nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE, password_bytes, salt_bytes, opslimit=ops, memlimit=mem,encoder=nacl.encoding.RawEncoder)
    return nacl.secret.SecretBox(key)


def encrypt_private_data(box):
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    prikeys =[cherrypy.session['signing_key'].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8'), ]
    if(cherrypy.session['blocked_message_signatures'] == None):
        blocked_pubkey= []
        blocked_usernames = []
        blocked_message_signatures = []
        blocked_words = []
        favourite_message_signatures = []
        friends_usernames = []

    privatedata = {
        "prikeys": prikeys,
        "blocked_pubkeys": blocked_pubkey,
        "blocked_usernames": blocked_usernames,
        "blocked_message_signatures": blocked_message_signatures,
        "blocked_words": blocked_words,
        "favourite_message_signatures":favourite_message_signatures,
        "friends_usernames": friends_usernames,
    }

    message = json.dumps(privatedata).encode('utf-8')
    encrypted = box.encrypt(message, nonce)

    print("------------asserting --------------------------\n")

    return base64.b64encode(encrypted).decode('utf-8')


def decrypt_private_data(box,encrypted_data):
    privatedata = base64.b64decode(encrypted_data['privatedata'].encode('utf-8'))
    data = box.decrypt(privatedata)
    
    JSON_object = json.loads(data.decode('utf-8').replace("'","\""))

    cherrypy.session['signing_key'] = nacl.signing.SigningKey(JSON_object['prikeys'][0], encoder=nacl.encoding.HexEncoder)
    verify_key_hex = cherrypy.session['signing_key'].verify_key.encode(encoder=nacl.encoding.HexEncoder)
    cherrypy.session['pub_key'] = verify_key_hex.decode('utf-8')
    cherrypy.session['time_last_online'] = encrypted_data['client_saved_at']

    cherrypy.session['blocked_broadcast'] =  JSON_object['blocked_message_signatures']
    cherrypy.session['blocked_pubkeys'] = JSON_object['blocked_pubkeys']
    cherrypy.session['blocked_usernames'] = JSON_object['blocked_usernames']
    cherrypy.session['blocked_words'] = JSON_object['blocked_words']
    cherrypy.session['friends_usernames'] = JSON_object['friends_usernames']
    cherrypy.session['favourite_message_signatures'] = JSON_object['favourite_message_signatures']

def get_loginserver_record():
    url = "http://cs302.kiwi.land/api/get_loginserver_record"

    payload = {
    }

    cherrypy.session['loginserver_record'] = send(url, payload,5)['loginserver_record']


def ping_check(ip):
    url = "http://"+ip+"/api/ping_check"
    current_time = str(time.time())
    local_ip = str(socket.gethostbyname(socket.getfqdn())) +":10000"
    payload = {
        "my_time": current_time,
        "connection_address": local_ip,
        "connection_location": "2",
    }

    send(url, payload,0.5)

def read_posts():
    conn = sqlite3.connect('webapp')
    c = conn.cursor()
    posts = [[],[],[],[],[],[],[]]
    posts_blocking = [[], [], [], [], [], [], []]
    c.execute('SELECT * FROM broadcasts ORDER BY time_sent DESC LIMIT 20')
    data = c.fetchall()
    for i in range(len(data)):
        name, message, time_sent, signature,record = data[i]
        time_sent =time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(time_sent)))
        posts_blocking[0].append('')
        posts_blocking[1].append('')
        posts_blocking[2].append('')
        # original message data
        posts_blocking[3].append('0')
        posts_blocking[4].append('0')
        posts_blocking[5].append('0')
        posts_blocking[6].append('0')
        if(message[:5] == "!Meta"):

            meta = message.split(":")
            s = meta[2].replace('[', '')
            s = s.replace(']', '')

            if len(meta) == 3:
                if(meta[1] == "favourite_broadcast"):
                    try:
                        c.execute('SELECT * FROM broadcasts WHERE signature=?',[s, ])
                        broadcast = tuple(c.fetchone())
                        # retweeted message data
                        posts[0].append(name)
                        posts[1].append(message)
                        posts[2].append(time_sent)
                        name2, message2, time2, signature2, record2 = broadcast
                        time_sent2 =time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(time2)))
                        #original message data
                        posts[3].append(name2)
                        posts[4].append(message2)
                        posts[5].append(time_sent2)
                        posts[6].append(str('['+signature2+']'))
                    except:
                        # message data
                        posts[0].append(name)
                        posts[1].append('orginal post not found')
                        posts[2].append(time_sent)
                        #
                        posts[3].append('0')
                        posts[4].append('orginal post not found')
                        posts[5].append('0')
                        posts[6].append('0')
                if (meta[1] == "block_broadcast"):
                    if(name!=cherrypy.session['username']):
                        posts[0].append(name)
                        posts[1].append(message)
                        posts[2].append(time_sent)
                        posts[3].append("0")
                        posts[4].append("0")
                        posts[5].append("0")
                        posts[6].append(str('[' + signature + ']'))
                    else:
                        i += 1

                if meta[1] == "block_username":
                    posts_blocking[0].append(name)
                    posts_blocking[1].append(s)
                    posts_blocking[2].append(time_sent)
                    # original message data
                    posts_blocking[3].append('2')
                    posts_blocking[4].append('0')
                    posts_blocking[5].append('0')
                    posts_blocking[6].append('0')

                if meta[1] == "block_pubkey":
                    posts_blocking[0].append(name)
                    posts_blocking[1].append(s)
                    posts_blocking[2].append(time_sent)
                    # original message data
                    posts_blocking[3].append('2')
                    posts_blocking[4].append('0')
                    posts_blocking[5].append('0')
                    posts_blocking[6].append('0')

        else:
            if signature in cherrypy.session['blocked_broadcast']:
                # message dataencoder=nacl.encoding.HexEncoder
                posts[0].append('0')
                posts[1].append('0')
                posts[2].append('0')
                #
                posts[3].append('1')
                posts[4].append('orginal post not found')
                posts[5].append('1')
                posts[6].append('0')
            else:
                posts[0].append(name)
                posts[1].append(message)
                posts[2].append(time_sent)
                posts[3].append("0")
                posts[4].append("0")
                posts[5].append("0")
                posts[6].append(str('['+signature+']'))



    conn.close()
    cherrypy.session['posts_blocking'] = posts_blocking
    return posts

def search_db(find):
    conn = sqlite3.connect('webapp')
    c = conn.cursor()
    posts = [[],[],[]]
    c.execute('SELECT * FROM broadcasts WHERE senders_username=? ORDER BY time_sent DESC LIMIT 10', [find, ])
    data = c.fetchall()
    for i in range(len(data)):
        name, message, time, signature,record = data[i]
        posts[0].append(name)
        posts[1].append(message)
        posts[2].append(time)

    conn.close()
    cherrypy.session['found_post'] = posts

def read_private_messages():
    conn = sqlite3.connect('webapp')
    c = conn.cursor()
    posts = [[], [], [], [], [], [], []]
    posts_blocking = [[], [], [], [], [], [], []]
    c.execute('SELECT * FROM private_messages WHERE target_pubkey=? ORDER BY time_created DESC LIMIT 20', [cherrypy.session['pub_key'], ])
    data = c.fetchall()

    for i in range(len(data)):
        record, target_pubkey,target_username,encrypted_message, time_sent, signature = data[i]
        record = record.split(",")   
        person = cherrypy.session['users_online'][0][int(cherrypy.session['person'])]


        if(record[0] == person or (record[0]==cherrypy.session['username'] and target_username==person)):
            if(target_username == cherrypy.session['username']):
                name = cherrypy.session['users_online'][0][int(cherrypy.session['person'])]                
            else:  
                name = "Me:"	
            try:
                time_sent =time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(time_sent)))
                unseal_box= SealedBox(cherrypy.session['signing_key'].to_curve25519_private_key())
                message = unseal_box.decrypt((encrypted_message.encode('utf-8')),encoder=nacl.encoding.HexEncoder).decode('utf-8')
            
                message =message.replace("<", "&lt;").replace(">", "&gt;")

        
            except:
                message="error decrypting message"

            #defualts
            posts_blocking[0].append('')
            posts_blocking[1].append('')
            posts_blocking[2].append('')
            posts_blocking[3].append('0')
            posts_blocking[4].append('0')
            posts_blocking[5].append('0')
            posts_blocking[6].append('0')

            if (message[:5] == "!Meta"):

                meta = message.split(":")
                s = meta[2].replace('[', '')
                s = s.replace(']', '')

                if len(meta) == 3:
                    if (meta[1] == "favourite_broadcast"):
                        try:
                            c.execute('SELECT * FROM broadcasts WHERE signature=?', [s, ])
                            broadcast = tuple(c.fetchone())
                            # retweeted message data
                            posts[0].append(name)
                            posts[1].append(message)
                            posts[2].append(time_sent)
                            name2, message2, time2, signature2, record2 = broadcast
                            time_sent2 =time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(time2)))
                            # original message data
                            posts[3].append(name2)
                            posts[4].append(message2)
                            posts[5].append(time_sent2)
                            posts[6].append(str('[' + signature2 + ']'))
                        except:
                            # message data
                            posts[0].append(name)
                            posts[1].append('orginal post not found')
                            posts[2].append(time_sent)
                            #
                            posts[3].append('0')
                            posts[4].append('orginal post not found')
                            posts[5].append('0')
                            posts[6].append('0')
                    if (meta[1] == "block_broadcast"):
                        if (name == cherrypy.session['username']):
                            # message data
                            posts[0].append('0')
                            posts[1].append('0')
                            posts[2].append('0')
                            #
                            posts[3].append('1')
                            posts[4].append('<font color="red"> <h5> orginal post not found</h5> </font>')
                            posts[5].append('1')
                            posts[6].append('0')
                        else:
                            i += 1

                    if meta[1] == "block_username":
                        posts_blocking[0].append(name)
                        posts_blocking[1].append(s)
                        posts_blocking[2].append(time_sent)
                        # original message data
                        posts_blocking[3].append('2')
                        posts_blocking[4].append('0')
                        posts_blocking[5].append('0')
                        posts_blocking[6].append('0')

                    if meta[1] == "block_pubkey":
                        posts_blocking[0].append(name)
                        posts_blocking[1].append(s)
                        posts_blocking[2].append(time_sent)
                        # original message data
                        posts_blocking[3].append('2')
                        posts_blocking[4].append('0')
                        posts_blocking[5].append('0')
                        posts_blocking[6].append('0')

            else:

                posts[0].append(name)
                posts[1].append(message)
                posts[2].append(time_sent)
                posts[3].append("0")
                posts[4].append("0")
                posts[5].append("0")
                posts[6].append(str('[' + signature + ']'))
        else:
            posts_blocking[0].append('')
            posts_blocking[1].append('')
            posts_blocking[2].append('')
            posts_blocking[3].append('0')
            posts_blocking[4].append('0')
            posts_blocking[5].append('0')
            posts_blocking[6].append('0')

    conn.close()
    cherrypy.session['private_posts_blocking'] = posts_blocking
    return posts
