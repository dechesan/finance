import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

if __name__ == '__main__':
    app.run(debug=True)

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Get the user's portfolio
    portfolio = get_portfolio()

    # Get user's cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # Get the total value of the user's portfolio + cash held
    total = cash
    for row in portfolio:
        total += row['total']

    # Send rows, cash, total
    return render_template("index.html", portfolio=portfolio, cash=cash, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting the buy form)
    if request.method == "POST":
        # Make sure user entered a symbol
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("missing symbol")
        
        # Look up symbol on Yahoo Finance using helper function
        share = lookup(symbol)

        # Make sure symbol is valid
        if not share:
            return apology("invalid symbol")
        
        # Make sure user entered the number of shares they wish to buy
        shares_buying = request.form.get("shares")
        if not shares_buying:
            return apology("missing shares")
        
        # Make sure user entered an integer
        if not shares_buying.isdigit():
            return apology("enter a whole number")

        # Change from string to int
        shares_buying = int(shares_buying)
        
        # Make sure user entered positive number
        if shares_buying < 1:
            return apology("enter positive number")
        
        # Get share price
        price = share["price"]

        # Get user's current cash
        user_cash_before = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # The amount of money the user needs in order to complete the transaction
        cash_needed = price * shares_buying

        # User's cash after transaction
        user_cash_after = user_cash_before - cash_needed

        # Check and handle if the user can't afford the transaction
        if user_cash_after < 0:
            return apology("need more moneyz")

        # Deduct the cash from the user
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash_after, session["user_id"])

        # Log transaction in transaction table
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, datetime) VALUES (?, ?, ?, ?, datetime('now'))",
            session["user_id"], symbol.upper(), shares_buying, price
        )

        # Store message to display to user on the next page
        flash("Bought!")

        # Return user to their portfolio page
        return redirect("/")
    
    # User reached route via GET
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # Get all transactions for the user from the DB
    transactions = db.execute("SELECT symbol, shares, price, datetime FROM transactions WHERE user_id = ?", session["user_id"])

    # Render the results
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    # User reached route via POST (as by submitting the quote form)
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # Make sure user didn't submit an empty form
        if not symbol:
            return apology("missing symbol")
        
        # Look up the symbol on Yahoo finance using helper function
        share = lookup(symbol)

        # Make sure symbol is valid
        if not share:
            return apology("invalid symbol")
        
        # Display the quote
        return render_template("quoted.html", symbol=share["symbol"], price=usd(share["price"]))

    # User reached route via GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting the registration form)
    if request.method == "POST":
        # Make sure username is not blank
        if not request.form.get("username"):
            return apology("must provide username")
        
        # Make sure username doesn't already exist
        if len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("username already exists")
        
        # Make sure neither the password or the confirmation are blank
        if not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must enter password twice")
        
        # Make sure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("must enter matching passwords")
        
        # Generate hash of password to avoid saving the actual password directly in the db
        password_hash = generate_password_hash(request.form.get("password"))

        # Add the user to the db
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password_hash)
        
        # Return user to homepage
        return redirect("/")
    
    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Get the user's portfolio
    portfolio = get_portfolio()

    # List of all symbols currently owned by the user
    symbols = []

    # Populate list of symbols owned by the user
    for row in portfolio:
        symbols.append(row['symbol'])
    
    # User reached route via POST (as by submitting the sell form)
    if request.method == "POST":
        # Get the symbol entered by the user of the stock they wish to sell
        symbol = request.form.get("symbol")
        
        # Make sure the user actually entered a symbol
        if not symbol:
            return apology("missing symbol")
        
        # Make sure the user entered a symbol for a stock they own
        if symbol not in symbols:
            return apology("invalid symbol")
        
        # Get the amount of shares entered by the user
        shares_selling = request.form.get("shares")

        # Make sure there is input for share amount
        if not shares_selling:
            return apology("missing shares")
        
        # Make sure user entered an integer
        if not shares_selling.isdigit():
            return apology("invalid 'shares' input")
        
        # Convert value to int
        shares_selling = int(shares_selling)
        
        # Make sure user entered a valid number of shares to sell
        if shares_selling < 1:
            return apology("shares less than 1")

        # Initializing variable for the shares held by the user of their selected stock
        shares_held_before = 0

        # Initializing variable for the current price of the selected stock
        price = 0

        # Get the number and price of shares held by the user for their selected stock 
        for row in portfolio:
            if row['symbol'] == symbol:
                shares_held_before = row['shares']
                price = row['price']

        # Confirm that the user has enough shares to sell
        if shares_held_before < shares_selling:
            return apology("insufficient shares")

        # Sell the shares
        cash_held_before = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        cash_gained = shares_selling * price
        cash_held_after = cash_held_before + cash_gained

        # Add cash to the user's account
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_held_after, session["user_id"])

        # Log the transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, datetime) VALUES (?, ?, ?, ?, datetime('now'))",
                   session["user_id"], symbol, (shares_selling * -1), price)

        # Store message to display to user on the next page
        flash("Sold!")

        # Redirect user to homepage
        return redirect("/")
    
    # User reached route via GET
    else:
        return render_template("sell.html", symbols=symbols)


@app.route("/funds", methods=["GET", "POST"])
@login_required
def funds():
    """ Show option to add more cash to account """

    # User reached route via POST (as by submitting the form to add funds)
    if request.method == "POST":
        # Get the user's input
        cash_adding = request.form.get("cash")

        # Make sure the user didn't submit a blank form
        if not cash_adding:
            return apology("missing amount")
        
        # Make sure user entered a number
        try:
            cash_adding = float(cash_adding)
        except ValueError:
            return apology("enter a number")
        
        # Make sure the user entered at least 1 dollar
        if cash_adding < 1:
            return apology("minimum amount is $1.00")
        
        # Get the user's current cash from the DB, and add the new funds to that amount
        new_total = float(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]) + cash_adding
        
        # Update the user's cash amount in the DB
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_total, session["user_id"])

        # Store message to be displayed on the next page load
        flash(f"Funds added: ${cash_adding:,.2f}")

        # Redirect user to homepage
        return redirect("/")
    
    # User reached route via GET
    else:
        # Display the form to add funds
        return render_template("funds.html")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
     """ Show settings for the user's account """

    # User reached route via POST (as by submitting the form to change password)
     if request.method == "POST":

        # Get user's input
        old_pass = request.form.get("old_pass")
        new_pass = request.form.get("new_pass")
        confirmation = request.form.get("confirmation")

        # Make sure user filled in all fields
        if not old_pass:
            return apology("please enter old password")
        if not new_pass:
            return apology("please enter new password")
        if not confirmation:
            return apology("please re-enter new password")
        
        # Make sure user re-entered the same password
        if not new_pass == confirmation:
            return apology("passwords do not match")
        
        # Get the hash of the old password from DB
        old_hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]

        # Check if the old password entered by the user is correct
        if not check_password_hash(old_hash, old_pass):
            return apology("old password is incorrect")
        
        # Make a hash for the new password
        new_hash = generate_password_hash(new_pass)

        # Update DB with new hash
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        # Store message to be displayed on next page load
        flash("Password Updated!")

        # Reload page
        return redirect("/settings")
     
     # User reached page via GET
     else:
        return render_template("settings.html")


def get_portfolio():
    # Get the symbols from all of the user's transactions. Returns list of dicts
    symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol", session["user_id"])

    # Convert list of dicts into a list of all dict values using list comprehension
    symbols = [(d['symbol']) for d in symbols]

    # Will store all of the user's stocks
    portfolio = []

    # Populate portfolio
    for symbol in symbols:
        shares = int(db.execute("SELECT SUM(shares) FROM transactions WHERE user_id = ? AND symbol=? GROUP BY symbol", session["user_id"], symbol)[0]['SUM(shares)'])
        if shares > 0:
            price = float(lookup(symbol)["price"])
            total = shares * price
            portfolio.append({'symbol': symbol, 'shares': shares, 'price': price, 'total': total})

    return portfolio