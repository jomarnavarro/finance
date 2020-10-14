import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, is_int, meets_complexity

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session['user_id']
    # get this select
    # select symbol, sum(num_shares) as num_shares from transactions where user_id = 1 GROUP BY symbol;
    # potential bug.  this will show symbols whose shares are greater than zero.
    rows = db.execute("SELECT symbol, sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING ns > 0",
        user_id=user_id)

    print(rows)
    # for every row, do the lookup, appending two keys for the dictionary: name and price
    grand_total = 0
    for row in rows:
        quote = lookup(row['symbol'])
        row['name'] = quote['name']
        row['price'] = quote['price']
        row['partial_total'] =  quote['price'] * row['ns']
        grand_total = grand_total + row ['partial_total']

    print(rows)
    cash_rows = db.execute("SELECT cash FROM users WHERE id = :id",
            id=user_id)

    print(cash_rows)

    cash = cash_rows[0]['cash']

    grand_total = grand_total + cash

    print(grand_total)
    # render the index.html template with the dictionary and the cash amount dictionary
    return render_template("index.html", stocks=rows, cash=cash, position=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'GET':
        return render_template("buy.html")
    else:
        symbol = request.form.get('symbol')
        qty = request.form.get('qty')
        if not is_int(qty) or int(qty) < 1:
            return apology("You must enter a number greater than 0", 402)
        else:
            qty = int(qty)

        if not symbol:
            return apology('You must enter a symbol')

        quote = lookup(symbol)
        if not quote:
             return apology(f"{symbol} is not valid", 403)

        # if Im here it means both the symbol and the qty are correct.
        # check if the user can afford the purchase.
        value = qty * quote['price']
        user_id = session['user_id']
        rows = db.execute("SELECT cash FROM users WHERE id = :id",
            id=user_id)
        print(rows)
        if len(rows) != 1:
            return apology("User does not exist", 500)
        cash = rows[0]['cash']

        if cash >= value:
            # update user cash
            cash_left = cash - value
            db.execute("UPDATE users SET cash = :cash_left WHERE id = :id ",
                cash_left=cash_left, id=user_id)
            # insert transaction into said table
            db.execute("INSERT INTO transactions (user_id, symbol, num_shares, price) VALUES (?, ?, ?, ?)",
                user_id, symbol.upper(), qty, quote['price'])
            return redirect("/")
        else:
            return apology(f"You are $ { value - cash } short for this transaction.", 402)



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT symbol, num_shares AS ns, price, time FROM transactions where user_id = :id ORDER BY time ASC",
        id=session['user_id'])
    return render_template("history.html", stocks=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template('quote.html')
    else:
        # get the symbol
        symbol = request.form.get('symbol')
        if not symbol:
            return apology("You must provide a symbol.", 400)
        quote = lookup(symbol)
        # print(quote)

        if not quote:
            quote = { 'symbol': symbol }

        return render_template('quoted.html', quote=quote)
        # query IEX for it.
        # if the return is None return an apology message

        # else show the quoted.html template with the information from IEX


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        repeat_password = request.form.get('repeat_password')
        if not username:
            return apology('You did not enter a username.', 403)
        if not password or not repeat_password:
            return apology('You did not enter a password.', 403)
        if password != repeat_password:
            return apology('Passwords do not match.', 403)
        if not meets_complexity(password):
            return apology('Password must: \n\t-be 8+ characters long.\n\t-contain uppercase and lowercase letters\n\t-a number and a symbol\n\n', 403)

        rows = db.execute("SELECT * FROM users WHERE username=:username",
            username=username)

        if len(rows) != 0:
            return apology(f"{username} is already taken", 403)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
            username, generate_password_hash(password))

        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'GET':
        # get the valid shares
        rows = db.execute("SELECT symbol, sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING ns > 0",
        user_id=session['user_id'])
        return render_template("sell.html", symbols=rows)
    else:
        symbol = request.form.get('symbol')
        if not symbol:
            return apology('Invalid symbol', 403)
        qty = request.form.get('qty')

        if not is_int(qty) or int(qty) < 1:
            return apology("You must enter a number greater than 0", 402)
        else:
            qty = int(qty)

        # Get the number of shares for this symbol
        rows = db.execute("SELECT sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
            user_id=session['user_id'], symbol=symbol)

        num_shares = rows[0]['ns']
        # check num_shares is not less than the quantity
        if num_shares < qty:
            return apology(f"You can't sell {qty} shares. You only have {num_shares}.", 402)
        # sell value
        quote = lookup(symbol)
        value = qty * quote['price']
        # get the cash and calculate the value of the shares
        rows = db.execute("SELECT cash FROM users WHERE id = :id",
            id=session['user_id'])
        cash = rows[0]['cash']
        new_cash = cash + value
        # update cash
        db.execute("UPDATE users SET cash = :cash_left WHERE id = :id ",
                cash_left=new_cash, id=session['user_id'])

        # insert the transaction with negative value num shares
        db.execute("INSERT INTO transactions (user_id, symbol, num_shares, price) VALUES (?, ?, ?, ?)",
                session['user_id'], symbol.upper(), qty * -1, quote['price'])

        return redirect('/')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
