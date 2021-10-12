from flask import Blueprint, render_template, render_template_string, request, redirect, url_for, session
import urllib
import requests
import os
import json

from CTFd.config import config_ini, empty_str_cast
from CTFd import challenges
from CTFd.auth import auth
from CTFd.plugins import register_plugin_assets_directory
from CTFd.models import Teams, UserFieldEntries, UserFields, Users, db
#from CTFd.models import db, Users
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils import validators
from CTFd.utils import user as current_user
from CTFd.utils.crypto import verify_password
from CTFd.utils.helpers import error_for, get_errors, markup, info_for
#from CTFd.utils import email
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.decorators.visibility import check_registration_visibility

from .services.google import GoogleOAuth

oauth = Blueprint("simple-oauth2", __name__)#, template_folder="templates")

plugin_dir = os.path.dirname(os.path.realpath(__file__))
templates_dir = os.path.join(plugin_dir, "templates")
#@oauth.route("/o/g/login")
#def g_oauth_login():
#    pass

#def render_login():

# default endpoint_path is "/o/g/redirect"
@oauth.route(GoogleOAuth.endpoint_path)
def oauth_login():

    response = GoogleOAuth.request_token()

    if response.status_code != 200:
        error_for(
            endpoint="auth.login", message="OAuth認証エラー"
        )
        return redirect(url_for("auth.login"))

    res_dict = dict(response.json())

    response = GoogleOAuth.request_email(token=res_dict["access_token"])

    if response.status_code != 200:
        error_for(
            endpoint="auth.login", message="トークン認証エラー"
        )
        return redirect(url_for("auth.login"))
    
    userdata = dict(response.json())


    email_address = userdata["email"]
    user_id = email_address.split("@")[0]
    valid_email = validators.validate_email(email_address)

    # if email exidts in table
    #if not valid_email:
    #    errors.append()

    emails = (
        Users.query.add_columns("email", "id")
            .filter_by(email=email_address)
            .first()
    )

    next_url = ""
    if email.check_email_is_whitelisted(email_address) is False:
        error_for(
            endpoint="auth.login", message="s.do-johodai.ac.jpのメールアドレスでログインしてください"
        )
        return redirect(url_for("auth.login"))

    if not emails:
        user = Users(
            name=user_id,
            email=email_address,
            verified=True
        )
        db.session.add(user)
        db.session.commit()
        db.session.flush()

        log("registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=user.name,
            email=user.email
        )

        db.session.close()
        info_for(
            endpoint="challenges.listing", message="Settingsよりユーザー名を変更できます、Good luck!"
        )
        #next_url = url_for("views.settings"))
    else:
        user = Users.query.filter_by(email=email_address).first()
    
    login_user(user)
    
    return redirect(url_for('challenges.listing'))


@oauth.route("/o/g/login")
def g_oauth_url():
    redirect_url = GoogleOAuth.auth_url()
    return redirect(redirect_url)

@oauth.route("/o/g/error")
def g_login_error():
    return "none"


#@oauth.route("/register")
#@check_registration_visibility
##@ratelimit(method="POST", limit=10, interval=5)
#def oauth_register():
#    if current_user.authed():
#        return redirect(url_for("challenges.listing"))
#    
#    oauth_url = GoogleOAuth.auth_url()
#    
#    return redirect(oauth_url)

#auth.register = oauth_register
   

#class OAuthUser(db.Model):
    
#    id = db.Column(db.Integer)
    

def alt_register():
    register_template = os.path.join(templates_dir, "register.html")
    return render_template_string(
        open(register_template).read(),
        #infos=["not allowed"],
        oauth_link=GoogleOAuth.auth_url()
    )

login_template = os.path.join(templates_dir, "login.html")
def alt_login():

    errors = get_errors()
    if current_user.authed():
        return redirect(url_for("challenges.listing"))

    errors = get_errors()
    if request.method == "POST":
        name = request.form["name"]

        # Check if the user submitted an email address or a team name
        if validators.validate_email(name) is True:
            user = Users.query.filter_by(email=name).first()
        else:
            user = Users.query.filter_by(name=name).first()

        if user:
            if user.password is None:
                errors.append(
                    "Your account was registered with a 3rd party authentication provider. "
                    "Please try logging in with a configured authentication provider."
                )
                return render_template_string(
                    open(login_template).read(), 
                    errors=errors
                )

            if user and verify_password(request.form["password"], user.password):
                session.regenerate()

                login_user(user)
                log("logins", "[{date}] {ip} - {name} logged in", name=user.name)

                db.session.close()
                if request.args.get("next") and validators.is_safe_url(
                    request.args.get("next")
                ):
                    return redirect(request.args.get("next"))
                return redirect(url_for("challenges.listing"))

            else:
                # This user exists but the password is wrong
                log(
                    "logins",
                    "[{date}] {ip} - submitted invalid password for {name}",
                    name=user.name,
                )
                errors.append("Your username or password is incorrect")
                db.session.close()
                return render_template_string(
                    open(login_template).read(),
                    errors=errors
                )
        else:
            # This user just doesn't exist
            log("logins", "[{date}] {ip} - submitted invalid account information")
            errors.append("Your username or password is incorrect")
            db.session.close()
            return render_template_string(
                open(login_template).read(),
                errors=errors
            )
    else:
        db.session.close()
        #return render_template("login.html", errors=errors)

        return render_template_string(
            open(login_template).read(),
            oauth_link=GoogleOAuth.auth_url(),
            errors=errors
        )



def load(app):
    register_plugin_assets_directory(app, base_path=os.path.join(plugin_dir, "assets"))
    #app.register_blueprint(auth, **{"url_defaults": {"/register": None}})
    app.view_functions['auth.register'] = alt_register
    app.view_functions['auth.login'] = alt_login
    #def alt_error():
    #    return str(vars(app.config))
    app.register_blueprint(oauth)
    #app.view_functions["simple-oauth2.g_login_error"] = alt_error