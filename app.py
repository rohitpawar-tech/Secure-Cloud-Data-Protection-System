
from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Generate encryption key (Run once & keep constant in real projects)
key = Fernet.generate_key()
cipher = Fernet(key)

# Initialize Database
def init_db():
    conn = sqlite3.connect("database.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.close()

@app.route("/")
def home():
    return redirect("/login")

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        # Layer 1: Password Hashing
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Layer 2: AES Encryption of email
        encrypted_email = cipher.encrypt(email.encode())

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:
            # SQL Injection Protected (Parameterized Query)
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                           (name, encrypted_email, hashed_pw))
            conn.commit()
        except:
            conn.close()
            return "User already exists!"

        conn.close()
        return redirect("/login")

    return render_template("register.html")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        conn.close()

        for user in users:
            decrypted_email = cipher.decrypt(user[2]).decode()

            if decrypted_email == email:
                if bcrypt.checkpw(password.encode('utf-8'), user[3]):
                    session["user"] = user[1]
                    return redirect("/dashboard")

        return "Invalid Credentials!"

    return render_template("login.html")

# DASHBOARD
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html", name=session["user"])
    return redirect("/login")

# LOGOUT
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
