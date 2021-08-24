import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, make_response
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime
import jwt
from functools import wraps

from helpers import apology, login_required, lookup, usd, is_int, meets_complexity, parse_data

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# creates secret key config
if os.environ.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
else:
    raise RuntimeError("SECRET_KEY Environment variable must be set.")
    
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

def token_required(f):
    """
    Decorate routes that require jwt token
    
    """
    @wraps(f)
    def deco_func(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            user_id = db.execute("SELECT * FROM users WHERE username = :username",
                          username=data['username'])[0]['id']
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(user_id, *args, **kwargs)
    
    return deco_func


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


@app.route('/api/portfolio', methods=['GET'])
@token_required
def get_portfolio(user_id):
    rows = db.execute("SELECT symbol, sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id GROUP BY symbol HAVING ns > 0",
        user_id=user_id)

    grand_total = 0
    for row in rows:
        quote = lookup(row['symbol'])
        row['name'] = quote['name']
        row['price'] = quote['price']
        row['partial_total'] = quote['price'] * row['ns']
        grand_total += row['partial_total']

    cash_rows = db.execute("SELECT cash FROM users WHERE id=:id",
            id=user_id)

    cash = cash_rows[0]['cash']

    grand_total = grand_total + cash
    return jsonify({'stocks': rows, 'cash': cash, 'position': grand_total})


@app.route('/api/buy', methods=['POST'])
@token_required
def api_buy(user_id):
    data = request.get_json()

    symbol = data['symbol']
    qty = data['qty']

    if not symbol or not qty or not is_int(qty):
        return jsonify({'message': 'You must provide both Symbol and Quantity'}), 422
    else:
        qty = int(qty)
    
    quote = lookup(symbol)
    if not quote:
        return jsonify({'message': f"{symbol} does not exist"})
    
    value = qty * quote['price']
    rows = db.execute("SELECT cash FROM users WHERE id = :id",
            id=user_id)
    if len(rows) != 1:
        return jsonify({"message": "User does not exist"})
    
    cash = rows[0]['cash']
    if cash >= value:
        # update user cash
        cash_left = cash - value
        db.execute("UPDATE users SET cash= :cash_left WHERE id = :id", cash_left=cash_left, id=user_id)
        # insert transaction into transactions table
        db.execute("INSERT INTO transactions (user_id, symbol, num_shares, price) VALUES (?,?,?,?)",
            user_id, symbol.upper(), qty, quote['price'])
        return jsonify({'message': f"You bought {qty} share(s) of {symbol}."}), 201
    else:
        return jsonify({'message': f"You are {value - cash} short for this transaction."}), 422


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
            flash("You must enter a number greater than 0")
            return redirect('/buy')
        else:
            qty = int(qty)

        if not symbol:
            flash('You must enter a symbol')
            return redirect('/buy')

        quote = lookup(symbol)
        if not quote:
            flash(f"{symbol} does not exist")
            return redirect('/buy')

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
            flash(f"You bought {qty} share(s) from {symbol}")    
            return redirect("/")
        else:
            flash(f"You are $ { value - cash} short for this transaction.")
            return redirect("/buy")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute("SELECT symbol, num_shares AS ns, price, time FROM transactions where user_id = :id ORDER BY time ASC",
        id=session['user_id'])
    
    return render_template("history.html", stocks=rows)


@app.route("/api/history", methods=['GET'])
@token_required
def api_history(user_id):
    """Show history of transactions"""
    rows = db.execute("SELECT symbol, num_shares AS ns, price, time FROM transactions where user_id = :id ORDER BY time ASC",
        id=user_id)
    transactions_list = []
    return jsonify({'transactions': rows}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("You must provide a username")
            return render_template('login.html')
            
        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("You must provide a password")
            return render_template('login.html')

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("invalid username and/or password")
            return render_template('login.html')

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        un = request.form.get('username')
        # Redirect user to home page
        flash(f"Welcome back {un}")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/api/login", methods=['POST'])
def api_login():
    # session.clear()
    user = request.json['username']
    passwd = request.json['password']
    print(f"username: {user}, password: {passwd}")

    if not user or not passwd:
        return jsonify({"error": "You must provide a valid username and password."}), 401
    rows = db.execute("SELECT * FROM users WHERE username = :username", username=user)
    if len(rows) != 1 or not check_password_hash(rows[0]['hash'], passwd):
        return jsonify({"error": "invalid username or password"}), 401
   
    token = jwt.encode({'username': user, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return jsonify({'token': token.decode('UTF-8')})
    

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route('/api/quote', methods=['POST'])
@token_required
def api_quote(user_id):
    symb = request.json['symbol']
    if not symb:
        return jsonify({'message': 'You must provide a symbol'}), 422
    quote = lookup(symb)

    if not quote:
        return jsonify({'message': f"{symb} is not a valid symbol"}), 422

    return jsonify(quote)


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
            flash("You must provide a symbol.")
            return redirect("/quote")
        quote = lookup(symbol)
        # print(quote)

        if not quote:
            flash(f"{symbol} is not a valid symbol.", 'error')
            return redirect('/quote')

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
        data = parse_data(request)

        # TODO validate cc and age
        # TODO validate extra data
        if not data['username']:
            flash('You did not enter a username.')
            return render_template('/register.html')
        if not data['password'] or not data['repeat_password']:
            flash('You did not enter a password.')
            return render_template('/register.html')
        if data['password'] != data['repeat_password']:
            flash('Passwords do not match.')
            return render_template('/register.html')
        # if not meets_complexity(password):
        #     return apology('Password must: \n\t-be 8+ characters long.\n\t-contain uppercase and lowercase letters\n\t-a number and a symbol\n\n', 403)

        rows = db.execute("SELECT * FROM users WHERE username=:username",
            username=data['username'])

        if len(rows) != 0:
            flash(f"{data['username']} is already taken")
            return render_template('/register.html')

        # TODO consider the scenario when 10 000 cash promotion is done
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
            data['username'], generate_password_hash(data['password']))
        # TODO add insertion to user_data table.  create user_data table as well

        # TODO send email to user with link to validate his account

        flash(f"{data['username']} was succesfully registered.")
        return render_template('login.html')


@app.route("/api/register", methods=["POST"])
@token_required
def api_register(user_id):
    """Register user"""
    data = request.get_json()
    print(data)

    # TODO validate cc and age
    # TODO validate extra data
    if not data['username']:
        return jsonify({'message': 'You must provide a username'}), 422
    if not data['password']:
        return jsonify({'message': 'You must provide a password'}), 422
    # if not meets_complexity(password):
    #     return apology('Password must: \n\t-be 8+ characters long.\n\t-contain uppercase and lowercase letters\n\t-a number and a symbol\n\n', 403)

    rows = db.execute("SELECT * FROM users WHERE username=:username",
        username=data['username'])

    if len(rows) != 0:
        return jsonify({'message': f'User {data["username"]} already registered.'}), 422

    # TODO consider the scenario when 10 000 cash promotion is done
    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
        data['username'], generate_password_hash(data['password']))
    # TODO add insertion to user_data table.  create user_data table as well

    # TODO send email to user with link to validate his account

    return jsonify({'message': f'User {data["username"]} has been registered.'}), 201


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
            flash("Wrong symbol")
            return redirect("/sell")
        qty = request.form.get('qty')

        if not is_int(qty) or int(qty) < 1:
            flash("You need to select a positive number")
            return redirect("/sell")
        else:
            qty = int(qty)

        # Get the number of shares for this symbol
        rows = db.execute("SELECT sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
            user_id=session['user_id'], symbol=symbol)

        num_shares = rows[0]['ns']
        # check num_shares is not less than the quantity
        if num_shares < qty:
            flash(f"You can't sell {qty} shares. You only have {num_shares}.")
            return redirect("/sell")
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
        flash(f"You sold {qty} share(s) from {symbol}")
        return redirect('/')


@app.route("/api/sell", methods=["POST"])
@token_required
def api_sell(user_id):
    """Sell shares of stock"""
    symbol = request.json['symbol']
    if not symbol:
        return jsonify({'message', 'You must provide a symbol'}), 422
    qty = request.json['qty']

    if not qty or not is_int(qty) or int(qty) < 1:
        return jsonify({'message': 'You must provide a valid quantity'}), 422
    else:
        qty = int(qty)

    # Get the number of shares for this symbol
    rows = db.execute("SELECT sum(num_shares) AS ns FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
        user_id=user_id, symbol=symbol)

    print(f"len rows {len(rows)}")

    if not rows:
        return jsonify({'message': f"You have no shares from {symbol}."}), 422

    num_shares = rows[0]['ns']
    # check num_shares is not less than the quantity
    if num_shares < qty:
        return jsonify({'message': f"You have only {num_shares} share(s) from {symbol}.  You can't sell {qty} share(s)."}), 422
        
    # sell value
    quote = lookup(symbol)
    value = qty * quote['price']
    # get the cash and calculate the value of the shares
    rows = db.execute("SELECT cash FROM users WHERE id = :id",
        id=user_id)
    cash = rows[0]['cash']
    new_cash = cash + value
    # update cash
    db.execute("UPDATE users SET cash = :cash_left WHERE id = :id ",
            cash_left=new_cash, id=user_id)

    # insert the transaction with negative value num shares
    db.execute("INSERT INTO transactions (user_id, symbol, num_shares, price) VALUES (?, ?, ?, ?)",
            user_id, symbol.upper(), qty * -1, quote['price'])
    return jsonify({'message': f"You sold {qty} share(s) from {symbol}"}), 201


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
