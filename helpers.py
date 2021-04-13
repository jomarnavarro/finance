import os
import requests
import urllib.parse
import re

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        api_key = os.environ.get("API_KEY")
        print(api_key)
        response = requests.get(f"https://cloud.iexapis.com/stable/stock/{urllib.parse.quote_plus(symbol)}/quote?token={api_key}")
        print(response)
        response.raise_for_status()
    except requests.RequestException:
        print("Error error error")
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["companyName"],
            "price": float(quote["latestPrice"]),
            "symbol": quote["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"


def is_int(s):
    """ checks whether a string is an int"""
    try:
        int(s)
        return True
    except ValueError:
        return False


def meets_complexity(password):
    return (len(password) < 8) and (re.search(r"\d", password) is None) and (re.search(r"[A-Z]", password) is None) and (re.search(r"[a-z]", password) is None) and (re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None)

def parse_data(request):
    return {
        "first_name": request.form.get('first_name'),
        "last_name": request.form.get('last_name'),
        "username": request.form.get('username'),
        "password": request.form.get('password'),
        "repeat_password": request.form.get('repeat_password'),
        "email": request.form.get('email'),
        "phone": request.form.get('phone'),
        "birthdate": request.form.get('birthdate'),
        "cc": request.form.get('cc'),
        "expiration": request.form.get('expiration'),
        "cvv": request.form["cvv"]
    }

