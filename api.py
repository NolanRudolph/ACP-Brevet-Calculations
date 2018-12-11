# Laptop Service
import os, acp_times, flask, password, testToken, math, json, base64
from flask import Flask, render_template, request, session, redirect, url_for, Response, make_response
from flask_restful import Resource, Api, reqparse, fields
from flask_login import LoginManager, UserMixin, current_user, login_user, fresh_login_required, login_required
from flask_wtf.csrf import CsrfProtect
from flask_wtf import FlaskForm
from pymongo import MongoClient

# Instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)
api = Api(app)

# CSRF Protection
csrf = CsrfProtect()

# api = Api(app, decorators=[csrf_protect.exempt])


app.secret_key = '56721329980543265787809923'
app.config['SESSION_TYPE'] = 'filesystem'

client = MongoClient(os.environ['DB_PORT_27017_TCP_ADDR'], 27017)
db = client.myDB
user_db = client.user_db


#########  USER ST00F  #########

# Things to consider

class User(UserMixin):
    def __init__(self, name, id, active=True):
        self.name = name
        self.id = id
        self.active = active

    def is_active(self):
        return self.active

login_manager = LoginManager()
login_manager.setup_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)



##########  WEBPAGES  ##########

# Temporary method for dumping database
@app.route('/dump', methods=['GET', 'POST'])
def dump():
    db.user_db.drop()
    db.myDB.drop()
    if session.get('token'):
        session.pop('token')
    return render_template('login.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


@app.route('/web_register', methods=['GET', 'POST'])
def web_register():
    return render_template('register.html')


@app.route('/_new_user', methods=['GET', 'POST'])
def _new_user():
    my_password = request.form['password']
    if my_password == "":
        return redirect(url_for('login')), 400

    encrypt_pass = password.hash_password(my_password)

    user_struct = {
        'username': request.form['username'],
        'password': encrypt_pass,
        'ip': None,
        'token': None
    }

    db.user_db.insert_one(user_struct)

    app.logger.debug("USER DATA BASE: ")
    _items = db.user_db.find()
    for item in _items:
        app.logger.debug(item)

    return redirect(url_for('login')), 201


@app.route('/supaLogin')
def supaLogin():
    return render_template('supaLogin.html')


@app.route('/web_check_auth', methods=['GET', 'POST'])
def web_check_auth():
    cur_user = request.form['username']
    cur_pass = request.form['password']
    exists = False
    temp_pass = None

    _items = db.user_db.find()
    for item in _items:
        if cur_user == item['username']:
            exists = True
            temp_pass = item['password']
            break;

    if not exists:
        app.logger.debug("There is no user by this name, try again.")
        return render_template("supaLogin.html")

    if password.verify_password(cur_pass, temp_pass):
        if request.form.get('rem') and request.form['rem']:
            app.logger.debug("Matched Password && Infinite Token Authentication!")
            t = testToken.generate_auth_token(math.inf)
            if session.get('token'):
                session.pop('token')
            session['token'] = t
            return redirect(url_for('setup'))
        else:
            app.logger.debug("Matched Password!")
            session['token'] = 'bad_token'
            t = testToken.generate_auth_token(600)
            if session.get('token'):
                session.pop('token')
            session['token'] = t
            return redirect(url_for('setup'))
    else:
        session['token'] = 'bad_token'
        app.logger.debug("Authentication Failure, try again.")

    return render_template("supaLogin.html")


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    db.myDB.drop()

    if session.get('begin_date'):
        session.pop('begin_date')
    session['begin_date'] = request.args.get('begin_date')
    app.logger.debug("Begin date is " + session['begin_date'])

    if session.get('begin_time'):
        session.pop('begin_time')
    session['begin_time'] = request.args.get('begin_time')
    app.logger.debug("Begin time is " + session['begin_time'])

    if session.get('total_distance'):
        session.pop('total_distance')
    session['total_distance'] = int(request.args.get('total_distance'))
    app.logger.debug("Total distance is " + str(session['total_distance']))
    return redirect(url_for('index'))


@app.route('/index', methods=['GET', 'POST'])
def index():
    if session.get('token'):
        if testToken.verify_auth_token(session['token']):
            return render_template('index.html')
    else:
        return render_template('nope.html')


@app.route("/_calc_times")
def _calc_times():
    """
    Calculates open/close times from miles, using rules
    described at https://rusa.org/octime_alg.html.
    Expects one URL-encoded argument, the number of miles.
    """
    app.logger.debug("Got a JSON request")
    km = request.args.get('km', 999, type=float)
    date = request.args.get('date', type=str)
    total_distance = request.args.get('distance', 1000, type=float)
    open_time = acp_times.open_time(km, total_distance, date)
    close_time = acp_times.close_time(km, total_distance, date)
    result = {"open": open_time, "close": close_time}
    return flask.jsonify(result=result)


@app.route('/new', methods=['POST'])
def new():

    app.logger.debug("session['begin_date'] = " + session['begin_date'])
    app.logger.debug("session['begin_time'] = " + session['begin_time'])
    app.logger.debug("session['total_distance'] = " + str(session['total_distance']))

    app.logger.debug("DATABASE LOGS:")
    _items = db.myDB.find()
    for item in _items:
        app.logger.debug(item)

    use_date = session['begin_date'] + "T" + session['begin_time']
    distance = int(request.form['distance'])
    total_distance = session['total_distance']

    if distance > total_distance:
        return redirect(url_for('index'))

    open_time = acp_times.open_time(distance, total_distance, use_date)
    close_time = acp_times.close_time(distance, total_distance, use_date)

    ret_open_time = "{}/{} {}:{}".format(open_time[5:7], open_time[8:10],
                                         open_time[11:13], open_time[14:16])

    ret_close_time = "{}/{} {}:{}".format(close_time[5:7], close_time[8:10],
                                         close_time[11:13], close_time[14:16])

    item_doc = {
        'open_time': ret_open_time,
        'close_time': ret_close_time,
        'name': request.form['name'],
        'description': request.form['description'],
        'distance': request.form['distance']
    }
    db.myDB.insert_one(item_doc)

    app.logger.debug("DATABASE LOGS:")
    _items = db.myDB.find()
    for item in _items:
        app.logger.debug(item)

    return redirect(url_for('index'))


@app.route('/nope', methods=['GET'])
def nope():
    return render_template('nope.html'), 401


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if session.get('token'):
        if testToken.verify_auth_token(session['token']):
            return render_template('setup.html')
    else:
        return redirect(url_for('nope'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if session.get('token'):
        session.pop('token')
    return redirect(url_for('login'))


def check_auth(username, my_pass):
    cur_user = username
    cur_pass = my_pass
    exists = False

    _items = db.user_db.find()
    for item in _items:
        if cur_user == item['username']:
            exists = True
            temp_pass = item['password']
            break

    if not exists:
        return {'message': "There is no user by this name, please try again.", 'auth': False}

    if password.verify_password(cur_pass, temp_pass):
        app.logger.debug("Matched Password!")
        return {'message': 'Hello, ' + str(cur_user) + '!', 'auth': True}

    else:
        return {'message': 'Incorrect password, please try again.', 'auth': False}


##########  RESTFUL API  ##########


class Register(Resource):
    def get(self):
        return render_template('register.html')

    def post(self):
        app.logger.debug(request.remote_addr)
        data = request.data
        data_dict = json.loads(data)

        username = data_dict['username']
        my_password = data_dict['password']

        if my_password == "":
            return redirect(url_for('login')), 400

        encrypt_pass = password.hash_password(my_password)

        user_struct = {
            'username': username,
            'password': encrypt_pass,
            'ip': request.remote_addr,
            'token': None
        }

        app.logger.debug("USER DATA BASE: ")
        _users = db.user_db.find()
        total = 1
        for user in _users:
            total += 1
            if username == user['username']:
                return "That name has already been taken! Try again.", 401

        db.user_db.insert_one(user_struct)

        ret_json = {'username': username, 'password': encrypt_pass}

        return ret_json, 201, {'Location': 'http://127.0.0.1:5000/api/user_db/' + str(total)}


class Token(Resource):
    def get(self):
        is_auth = None
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)
        elif session.get('token') and testToken.verify_auth_token(session['token']):
            t = testToken.generate_auth_token(600)
            session['token'] = t
            return t.decode("utf-8")
        else:
            return "This page is for authorized users only.", 401

        if is_auth:
            if is_auth['auth']:
                if session.get('token'):
                    session.pop('token')
                t = testToken.generate_auth_token(600)
                session['token'] = t

                ret_token = {
                    'duration': '600',
                    'token': t.decode("utf-8")
                }
                # Store that token for user
                _users = db.user_db.find()
                for user in _users:
                    if cur_user == user['username']:
                        db.user_db.update_one(
                            {'username': cur_user},
                            {"$set": {'token': t}}
                        )
                        break

                return ret_token
            else:
                return is_auth['message'], 401
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401

# Do Not Reinvent the Wheel
def DNRW(ip):
    token_cred = False
    ip_cred = False
    if session.get('token'):
        if testToken.verify_auth_token(session['token']):
            token_cred = True

    _items = db.user_db.find()
    for user in _items:
        if ip == user['ip']:
            if user['token']:
                if testToken.verify_auth_token(user['token']):
                    ip_cred = True
            else:
                app.logger.debug("Too many users on same IP")
        break

    return token_cred, ip_cred


class OpenClose(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
                parser = reqparse.RequestParser()
                parser.add_argument("top")
                args = parser.parse_args()
                k = args["top"]

                _items = db.myDB.find()
                items = [item for item in _items]

                open = []
                close = []

                if k != None:
                    if int(k) > len(items):
                        for item in items:
                            open.append(item['open_time'])
                            close.append(item['close_time'])
                    else:
                        stop = 0
                        for item in items:
                            if stop < int(k):
                                open.append(item['open_time'])
                                close.append(item['close_time'])
                                stop += 1
                            else:
                                break
                else:
                    for item in items:
                        open.append(item['open_time'])
                        close.append(item['close_time'])

                return {'Open': open, 'Close': close}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401



class OpenCloseCSV(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            ret_string = "Open: \n"

            # Open Times

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        temp = item['open_time'].split(" ")
                        ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            temp = item['open_time'].split(" ")
                            ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                            stop += 1
                        else:
                            break;

                ret_string += "\nClose: \n"

                # Close Times

                if int(k) > len(items):
                    for item in items:
                        temp = item['close_time'].split(" ")
                        ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            temp = item['close_time'].split(" ")
                            ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                            stop += 1
                        else:
                            break;
            else:
                for item in items:
                    temp = item['open_time'].split(" ")
                    ret_string += (temp[0] + ',' + temp[1] + os.linesep)

                ret_string += "\nClose: \n"

                for item in items:
                    temp = item['close_time'].split(" ")
                    ret_string += (temp[0] + ',' + temp[1] + os.linesep)

            return Response(ret_string, mimetype="text/csv")
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class OpenCloseJSON(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            open = []
            close = []

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        open.append(item['open_time'])
                else:
                    stop1 = 0
                    for item in items:
                        if stop1 < int(k):
                            open.append(item['open_time'])
                            stop1 += 1
                        else:
                            break

                if int(k) > len(items):
                    for item in items:
                        close.append(item['close_time'])
                else:
                    stop2 = 0
                    for item in items:
                        if stop2 < int(k):
                            close.append(item['close_time'])
                            stop2 += 1
                        else:
                            break
            else:
                for item in items:
                    open.append(item['open_time'])
                    close.append(item['close_time'])

            return {'Open': open, 'Close': close}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class Open(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            open = []

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        open.append(item['open_time'])
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            open.append(item['open_time'])
                            stop += 1
                        else:
                            break
            else:
                for item in items:
                    open.append(item['open_time'])

            return {'Open': open}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class OpenCSV(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            open1 = []
            ret_string = "Open: \n"

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        open1.append(item['open_time'])
                        temp = item['open_time'].split(" ")
                        ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            open1.append(item['open_time'])
                            temp = item['open_time'].split(" ")
                            ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                            stop += 1
                        else:
                            break
            else:
                for item in items:
                    open1.append(item['open_time'])
                    temp = item['open_time'].split(" ")
                    ret_string += (temp[0] + ',' + temp[1] + os.linesep)

            return Response(ret_string, mimetype="text/csv")
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class OpenJSON(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            open = []

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        open.append(item['open_time'])
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            open.append(item['open_time'])
                            stop += 1
                        else:
                            break
            else:
                for item in items:
                    open.append(item['open_time'])

            return {'Open': open}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class Close(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            close = []

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        close.append(item['close_time'])
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            close.append(item['close_time'])
                            stop += 1
                        else:
                            break
            else:
                for item in items:
                    close.append(item['close_time'])

            return {'Close': close}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class CloseCSV(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            ret_string = "Close: \n"

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        temp = item['close_time'].split(" ")
                        ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            temp = item['close_time'].split(" ")
                            ret_string += (temp[0] + ',' + temp[1] + os.linesep)
                            stop += 1
                        else:
                            break;
            else:
                for item in items:
                    temp = item['close_time'].split(" ")
                    ret_string += (temp[0] + ',' + temp[1] + os.linesep)

            return Response(ret_string, mimetype="text/csv")
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


class CloseJSON(Resource):
    def get(self):
        is_auth = False
        token_cred, ip_cred = DNRW(request.remote_addr)
        if request.authorization:
            cur_user = request.authorization['username']
            cur_pass = request.authorization['password']
            is_auth = check_auth(cur_user, cur_pass)

        if is_auth and not is_auth['auth']:
            return "This page is for authorized users only.", 401

        if is_auth and is_auth['auth'] or token_cred or ip_cred:
            parser = reqparse.RequestParser()
            parser.add_argument("top")
            args = parser.parse_args()
            k = args["top"]

            _items = db.myDB.find()
            items = [item for item in _items]

            close = []

            if k != None:
                if int(k) > len(items):
                    for item in items:
                        close.append(item['close_time'])
                else:
                    stop = 0
                    for item in items:
                        if stop < int(k):
                            close.append(item['close_time'])
                            stop += 1
                        else:
                            break
            else:
                for item in items:
                    close.append(item['close_time'])

            return {'Close': close}
        else:
            if is_auth:
                return is_auth['message'], 401
            else:
                return "This page is for authorized users only.", 401


api.add_resource(Register, '/api/register')
api.add_resource(Token, '/api/token')
api.add_resource(OpenClose, '/api/listAll')
api.add_resource(OpenCloseCSV, '/api/listAll/csv')
api.add_resource(OpenCloseJSON, '/api/listAll/json')
api.add_resource(Open, '/api/listOpenOnly')
api.add_resource(OpenCSV, '/api/listOpenOnly/csv')
api.add_resource(OpenJSON, '/api/listOpenOnly/json')
api.add_resource(Close, '/api/listCloseOnly')
api.add_resource(CloseCSV, '/api/listCloseOnly/csv')
api.add_resource(CloseJSON, '/api/listCloseOnly/json')

# Run the application
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)


