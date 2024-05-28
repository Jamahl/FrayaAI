import os
import json
from flask import Flask, redirect, url_for, render_template, session, request, jsonify
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from supabase import create_client, Client
from google.oauth2.credentials import Credentials as GoogleCredentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import logging
from flask_talisman import Talisman

# Load environment variables from .env file
load_dotenv()

# Check if all environment variables are loaded
required_env_vars = ["SECRET_KEY", "SUPABASE_URL", "SUPABASE_KEY", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Initialize Flask app
app = Flask(__name__, template_folder='myapp/templates', static_folder='static')
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# Enforce HTTPS
talisman = Talisman(app)

# Allow insecure transport for OAuth2 during development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Supabase Setup
supabase: Client = create_client(os.environ.get('SUPABASE_URL'), os.environ.get('SUPABASE_KEY'))

# Setup OAuth for Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send'}
)

# Define SCOPES for OAuth
SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/calendar.events',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send'
]

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def refresh_access_token(credentials):
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            logging.debug("Access token refreshed successfully.")
            return credentials
        except Exception as e:
            logging.error(f"Failed to refresh access token: {e}")
            return None
    return credentials

def save_credentials(credentials):
    session['credentials'] = credentials_to_dict(credentials)

def credentials_to_dict(credentials):
    """Convert credentials to dictionary for storage in session."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

def credentials_from_dict(credentials_dict):
    """Convert dictionary to Credentials object."""
    return GoogleCredentials(
        token=credentials_dict['token'],
        refresh_token=credentials_dict['refresh_token'],
        token_uri=credentials_dict['token_uri'],
        client_id=credentials_dict['client_id'],
        client_secret=credentials_dict['client_secret'],
        scopes=credentials_dict['scopes']
    )

@app.route('/')
def index():
    try:
        app.logger.debug("Accessing index route")
        if 'user' not in session:
            return render_template('index.html')
        else:
            if 'credentials' in session:
                credentials = credentials_from_dict(session['credentials'])
                credentials = refresh_access_token(credentials)
                if credentials:
                    save_credentials(credentials)
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('login'))
            else:
                return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"An error occurred in index: {e}")
        return f"An error occurred: {e}", 500

@app.route('/login')
def login():
    """Redirect to Google OAuth login."""
    try:
        redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
        app.logger.debug(f"Constructed redirect URI: {redirect_uri}")

        flow = Flow.from_client_secrets_file(
            'client_secrets.json', scopes=SCOPES, redirect_uri=redirect_uri
        )
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        session['state'] = state
        app.logger.debug(f"Authorization URL: {authorization_url}")
        return redirect(authorization_url)
    except Exception as e:
        app.logger.error(f"An error occurred during login redirect: {e}")
        return f"An error occurred during login redirect: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handle response from Google OAuth."""
    try:
        app.logger.debug("OAuth2 callback initiated")
        
        if 'state' not in session or session['state'] != request.args.get('state'):
            app.logger.error("State mismatch or missing.")
            return "State mismatch or missing.", 403

        redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
        app.logger.debug(f"OAuth2 callback redirect URI: {redirect_uri}")

        flow = Flow.from_client_secrets_file(
            'client_secrets.json', 
            scopes=SCOPES, 
            state=session['state'], 
            redirect_uri=redirect_uri
        )
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Store the credentials in session
        save_credentials(credentials)
        
        # Use the Google API client to fetch user info
        user_info = google.get('userinfo', token=credentials.token).json()
        app.logger.debug(f"User info: {user_info}")

        user_data = {
            'GoogleOAuthToken': credentials.token,
            'FullName': f"{user_info['given_name']} {user_info['family_name']}",
            'Email': user_info['email']
        }
        response = supabase.table('users').upsert(user_data).execute()
        if response.error:
            raise Exception(response.error.message)
        app.logger.debug(f"User data inserted into Supabase: {user_data}")

        session['user'] = user_info
        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"An error occurred during authorization: {e}")
        return f"An error occurred during authorization: {e}", 500

@app.route('/dashboard')
def dashboard():
    """Ensure the user is logged in to view this page."""
    try:
        if 'user' not in session:
            return redirect(url_for('index'))
        
        if 'credentials' in session:
            credentials = credentials_from_dict(session['credentials'])
            credentials = refresh_access_token(credentials)
            if credentials:
                save_credentials(credentials)
                return render_template('dashboard.html', user=session['user'])
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"An error occurred while accessing the dashboard: {e}")
        return f"An error occurred while accessing the dashboard: {e}", 500

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    """Handle user preferences."""
    try:
        if request.method == 'POST':
            user = session.get('user')
            if user:
                preferences_data = {
                    'MeetingDuration': request.form.get('MeetingDuration'),
                    'cc_included': request.form.get('cc_included') == 'on',
                    'timezone': request.form.get('timezone'),
                    'PreferredTime': request.form.get('PreferredTime'),
                    'PreferredDays': json.dumps(request.form.getlist('PreferredDays')),
                    'FollowupFrequency': request.form.get('FollowupFrequency'),
                    'UserID': user['UserID']
                }
                response = supabase.table('preferences').upsert(preferences_data).execute()
                if response.error:
                    raise Exception(response.error.message)
                app.logger.debug(f"Preferences data saved: {preferences_data}")
                return redirect(url_for('dashboard'))
        return render_template('preferences.html')
    except Exception as e:
        app.logger.error(f"An error occurred while saving preferences: {e}")
        return f"An error occurred while saving preferences: {e}", 500

@app.route('/logout')
def logout():
    """Log out the user and clear the session."""
    try:
        session.clear()
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"An error occurred during logout: {e}")
        return f"An error occurred during logout: {e}", 500

if __name__ == "__main__":
    app.run(debug=True, port=80)
