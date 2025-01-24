from flask import Flask, render_template, url_for, session, redirect, request
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token
from googleapiclient.discovery import build
import os
import pathlib
import requests
import json

app = Flask(__name__)
app.secret_key = "your-secret-key@12344321"  

# Google OAuth2 credentials
CLIENT_SECRETS_FILE = "client_secret.json"  # Download this from GCP
GOOGLE_CLIENT_ID = "9792465820-qnvrp2qh51v9ssbeehgmn819h3s88641.apps.googleusercontent.com"

# OAuth2 configuration with just Drive scope
flow = Flow.from_client_secrets_file(
    client_secrets_file=CLIENT_SECRETS_FILE,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile", 
        "https://www.googleapis.com/auth/userinfo.email", 
        "openid",
        "https://www.googleapis.com/auth/drive"  # Full Drive access
    ],
    redirect_uri="https://marketingforai.onrender.com/callback"
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
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

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

@app.route("/drive")
def drive():
    if 'credentials' not in session:
        return redirect(url_for('login'))

    # Build the Drive API service
    credentials = google.oauth2.credentials.Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=credentials)

    try:
        # Call the Drive API
        results = drive_service.files().list(
            pageSize=100,
            fields="nextPageToken, files(id, name, mimeType, modifiedTime, size)",
            orderBy="modifiedTime desc"
        ).execute()
        files = results.get('files', [])

        # Update credentials in session
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        return render_template('drive.html', files=files)
    except Exception as e:
        print(f"An error occurred: {e}")
        return redirect(url_for('index'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for development
    app.run(debug=True)
