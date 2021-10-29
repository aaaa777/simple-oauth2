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

oauth = Blueprint("simple-oauth2", __name__)

plugin_dir = os.path.dirname(os.path.realpath(__file__))
templates_dir = os.path.join(plugin_dir, "templates")
#@oauth.route("/o/g/login")
#def g_oauth_login():
#    pass

#def render_login():

# default endpoint_path is "/o/g/redirect"
@oauth.route(GoogleOAuth.endpoint_path)
def oauth_login():

    # gets row response including token from google oauth
    # "code" and "scope" querys are given via request
    response = GoogleOAuth.request_token()

    # when something went wrong
    if response.status_code != 200:
        error_for(
            endpoint="auth.login", message="Sorry, Google OAuth login currentry unavailable."
        )
        return redirect(url_for("auth.login"))

    # request infomation with access_token
    res_dict = dict(response.json())
    response = GoogleOAuth.request_email(token=res_dict["access_token"])

    if response.status_code != 200:
        error_for(
            endpoint="auth.login", message="Sorry, Google OAuth login currentry unavailable."
        )
        return redirect(url_for("auth.login"))
    
    # response
    userdata = dict(response.json())

    email_address = userdata["email"]
    user_id = userdata["id"]
    valid_email = validators.validate_email(email_address)

    if email.check_email_is_whitelisted(email_address) is False:
        error_for(
            endpoint="auth.login", message="Sorry, Your mail address is restricted."
        )
        return redirect(url_for("auth.login"))

    # search for email from user table
    emails = (
        Users.query.add_columns("email", "id")
            .filter_by(email=email_address)
            .first()
    )

    if not emails:
        
        # create new user when not exists
        user = Users(
            name=user_id,
            email=email_address,
            verified=True
        )

        db.session.add(user)
        db.session.commit()
        db.session.flush()

        db.session.close()

        log("registrations",
            format="[{date}] {ip} - {name} registered with {email}",
            name=user.name,
            email=user.email
        )

        # set welcome messages
        info_for(
            endpoint="challenges.listing", message="Change your nickname from Settings, Good luck!"
        )
    else:

        # user exists
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

    
# the method to overwrite route of /register
def alt_register():

    # render from template from plugin
    register_template = os.path.join(templates_dir, "register.html")
    return render_template_string(
        open(register_template).read(),
        oauth_link=GoogleOAuth.auth_url()
    )

# the method to overwrite route of /login
login_template = os.path.join(templates_dir, "login.html")
def alt_login():

    # when user already logged in
    errors = get_errors()
    if current_user.authed():
        return redirect(url_for("challenges.listing"))

    # login attempt
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

                # render_template from /simple-oauth2/assets/login.html
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

                # render_template from /simple-oauth2/assets/login.html
                return render_template_string(
                    open(login_template).read(),
                    errors=errors
                )
        else:
            # This user just doesn't exist
            log("logins", "[{date}] {ip} - submitted invalid account information")
            errors.append("Your username or password is incorrect")
            db.session.close()
            
            # render_template from /simple-oauth2/assets/login.html
            return render_template_string(
                open(login_template).read(),
                errors=errors
            )
    else:
        db.session.close()

        # render_template from /simple-oauth2/assets/login.html
        return render_template_string(
            open(login_template).read(),
            oauth_link=GoogleOAuth.auth_url(),
            errors=errors
        )



def load(app):

    # set assets dir to /simple-oauth2/assets
    register_plugin_assets_directory(
        app,
        base_path="plugins/simple-oauth2/assets"
    )
    #app.register_blueprint(auth, **{"url_defaults": {"/register": None}})

    # overwrite routes
    app.view_functions['auth.register'] = alt_register
    app.view_functions['auth.login'] = alt_login
    
    # confirm blueprint
    app.register_blueprint(oauth)