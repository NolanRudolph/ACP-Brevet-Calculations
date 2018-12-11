from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)
import time

# initialization
# app = Flask(__name__)
# app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'


def generate_auth_token(expiration=600):
    # s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
    s = Serializer('test1234@#$', expires_in=expiration)
    # pass index of user
    return s.dumps({'id': 1})


def verify_auth_token(token):
    s = Serializer('test1234@#$')
    try:
        data = s.loads(token)
    except SignatureExpired:
        return None    # valid token, but expired
    except BadSignature:
        return None    # invalid token
    return "Success"

# if __name__ == "__main__":
#     t = generate_auth_token(10)
#     for i in range(1, 20):
#        print(verify_auth_token(t))
#        time.sleep(1)
