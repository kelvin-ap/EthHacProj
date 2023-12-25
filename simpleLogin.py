from flask import Flask, render_template, request

app = Flask(__name__)

# Hardcoded user credentials
valid_username = "admin"
valid_password = "uiopuiop"

# Variable to track if the login is wrong
wrong_password = False

@app.route("/", methods=["GET", "POST"])
def login():
    global wrong_password

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username == valid_username and password == valid_password:
            # Successful login, reset wrong password variable
            wrong_password = False
            return "Login successful!"
        else:
            # Wrong login, set wrong password variable to True
            wrong_password = True

    # Render the login template with the wrong_password variable
    return render_template("login.html", wrong_password=wrong_password)

if __name__ == "__main__":
    app.run(debug=True)
