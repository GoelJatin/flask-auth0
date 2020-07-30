"""Running the flask server."""

from functools import wraps

import os
import json

from flask import (
    Flask,
    redirect,
    render_template,
    session,
    url_for
)
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=os.getenv('AUTH0_CLIENT_ID'),
    client_secret=os.getenv('AUTH0_CLIENT_SECRET'),
    api_base_url=os.getenv('AUTH0_DOMAIN'),
    access_token_url=f'{ os.getenv("AUTH0_DOMAIN") }/oauth/token',
    authorize_url=f'{ os.getenv("AUTH0_DOMAIN") }/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# Here we're using the /callback route.


@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/login')
def login():
    return auth0.authorize_redirect(
        redirect_uri=os.getenv('AUTH0_CALLBACK_URL')
    )


def requires_auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/')
        return func(*args, **kwargs)

    return decorated


@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template(
        'dashboard.html',
        userinfo=session['profile'],
        userinfo_pretty=json.dumps(
            session['jwt_payload'],
            indent=4
        )
    )


@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {
        'returnTo': url_for(
            'index',
            _external=True
        ),
        'client_id': os.getenv('AUTH0_CLIENT_ID')}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


if __name__ == '__main__':
    app.secret_key = os.getenv('SECRET_KEY')
    app.run(host='0.0.0.0', port=8000)
