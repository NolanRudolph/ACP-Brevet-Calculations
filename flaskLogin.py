"""
Flask-Login example
===================
This is a small application that provides a trivial demonstration of
Flask-Login, including remember me functionality.

:copyright: (C) 2011 by Matthew Frazier.
:license: MIT/X11, see LICENSE for more details.
:source: https://gist.github.com/robbintt/32074560e52e46788237
"""
from flask import Flask, request, render_template, redirect, url_for, flash
from flask_login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, 
                            confirm_login, fresh_login_required)

# your user class 
class User(UserMixin):
    def __init__(self, name, id, active=True):
        self.name = name
        self.id = id
        self.active = active

    def is_active(self):
        return self.active

# note that the ID returned must be unicode
USERS = {
    1: User(u"A", 1),
    2: User(u"B", 2),
}

USER_NAMES = dict((u.name, u) for u in USERS.itervalues())

app = Flask(__name__)

SECRET_KEY = "yeah, not actually a secret"
DEBUG = True

app.config.from_object(__name__)

# step 1 in slides
login_manager = LoginManager()

# step 6 in the slides
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

# step 2 in slides 
@login_manager.user_loader
def load_user(id):
    return USERS.get(int(id))

login_manager.setup_app(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/secret")
@fresh_login_required
def secret():
    return render_template("secret.html")

# step 3 in slides
# This is one way. Using WTForms is another way.
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST" and "username" in request.form:
        username = request.form["username"]
        if username in USER_NAMES:
            remember = request.form.get("remember", "no") == "yes"
            if login_user(USER_NAMES[username], remember=remember):
                flash("Logged in!")
                return redirect(request.args.get("next") or url_for("index"))
            else:
                flash("Sorry, but you could not log in.")
        else:
            flash(u"Invalid username.")
    return render_template("login.html")

# step 5 in slides
@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    return render_template("reauth.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
