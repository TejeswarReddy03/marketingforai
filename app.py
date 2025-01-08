from flask import Flask, render_template, url_for, session, redirect, request
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token
import os
import pathlib
import requests
import json

app = Flask(__name__)
app.secret_key = "your-secret-key@12344321"  

# Google OAuth2 credentials
CLIENT_SECRETS_FILE = "client_secret.json"  # Download this from GCP
GOOGLE_CLIENT_ID = "9792465820-qnvrp2qh51v9ssbeehgmn819h3s88641.apps.googleusercontent.com"  # Replace with your client ID

# OAuth2 configuration
flow = Flow.from_client_secrets_file(
    client_secrets_file=CLIENT_SECRETS_FILE,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        return redirect(url_for("index"))  # State doesn't match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials.id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    # Clear specific session variables
    session.pop('google_id', None)
    session.pop('name', None)
    session.pop('email', None)
    session.pop('picture', None)
    session.pop('is_logged_in', None)
    session.pop('state', None)
    
    # Or clear entire session
    session.clear()
    
    # Redirect to home page
    return redirect(url_for('index'))

if __name__ == "__main__":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development
    app.run(debug=True)