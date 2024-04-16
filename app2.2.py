import psycopg2
from flask import Flask, request, jsonify ,render_template,redirect ,url_for, session 
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import secrets 
import json
import random
import string

app = Flask(__name__)
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/home')
def home_page():
    return render_template('home.html')

@app.route('/login_page_render')
def login_page_render():
    return render_template('login.html')

@app.route('/sign_up_page')
def sign_up_page():
    return render_template('sign_up.html')

@app.route('/forgot_password_page')
def forgot_password_page():
    return render_template('forgot_password1.html')

@app.route('/reset_password_token_page/<token>')
def reset_password_token_page(token):
    return render_template('reset_password2.html', token=token)

@app.route('/update_profile_page')
def update_profile_page():
    return render_template('update_profile.html')

# Configurația pentru Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'vasilesibaev@gmail.com'
app.config['MAIL_PASSWORD'] = 'ygiy pjpr oaww reaj'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# Funcție pentru generarea token-ului de resetare a parolei
def generate_reset_token():
    return secrets.token_urlsafe(32)

# Funcție pentru a obține o conexiune la baza de date
def get_db_connection():
    try:
        connection = psycopg2.connect(connection_string)
        return connection
    except psycopg2.Error as error:
        print("Eroare la conectare la baza de date:", error)
        return None

@app.route('/signup', methods=['POST'])
def signup():
    connection = get_db_connection()
    if connection:
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        session['email'] = email
        try:
            cursor = connection.cursor()
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)", (username, email, password_hash))
            connection.commit()
            cursor.close()
            connection.close()
            return render_template('home.html')
            
        except psycopg2.Error as e:
            print("Eroare la inserarea utilizatorului în baza de date:", e)
            connection.rollback()
            connection.close()
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "Failed to connect to database"}), 500
        

app.secret_key = 'your_very_secret_key_here'

@app.route('/login', methods=['POST'])
def login():
    connection = get_db_connection()
    if connection:
        email = request.form['email']
        password = request.form['password']
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            if user:
                if bcrypt.check_password_hash(user[3], password):
                    session['email'] = email
                    cursor.close()
                    connection.close()
                    return redirect(url_for('home_page'))
                    return jsonify({"message": "Login successful"}), 200
                else:
                    cursor.close()
                    connection.close()
                    return jsonify({"error": "Invalid credentials"}), 401
            else:
                cursor.close()
                connection.close()
                return jsonify({"error": "User not found"}), 404
        except psycopg2.Error as e:
            print("Eroare la interogarea bazei de date pentru login:", e)
            connection.close()
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "Failed to connect to database"}), 500
        
@app.route('/logout')
def logout():
    # Remove email (or whichever key you're using) from session
    session.pop('email', None)
    # Redirect to home page, login page, or wherever you prefer
    return redirect(url_for('home_page'))

# Funcție pentru a trimite codul de resetare a parolei pe email
def send_reset_code(email, reset_code):
    msg = Message('Reset Password Request', sender='vasilesibaev@gmail.com', recipients=[email])
    msg.body = f"Your password reset code is: {reset_code}"
    mail.send(msg)

# Funcție pentru a obține o conexiune la baza de date
def get_db_connection():
    try:
        connection = psycopg2.connect(connection_string)
        return connection
    except psycopg2.Error as error:
        print("Error connecting to the database:", error)
        return None

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    reset_code = generate_reset_code()
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("UPDATE users SET reset_code = %s WHERE email = %s", (reset_code, email))
            connection.commit()
            cursor.close()
            connection.close()
            # Trimitem codul de resetare a parolei pe email
            send_reset_code(email, reset_code)
            return redirect(url_for('reset_password_token_page', token=reset_code))
        except psycopg2.Error as e:
            print("Error updating reset code in database:", e)
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({"error": "Failed to update reset code"}), 500
            return jsonify({"message": "Reset code sent to your email"}), 200
    else:
        return jsonify({"error": "Failed to connect to database"}), 500

@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
    email = request.form['email']
    new_password = request.form['new_password']
    connection = get_db_connection()
    if connection:
        cursor = connection.cursor()
        try:
            # Verificăm dacă token-ul și email-ul sunt valide înainte de a actualiza parola
            cursor.execute("SELECT * FROM users WHERE email = %s AND reset_code = %s", (email, token))
            user = cursor.fetchone()
            if user:
                # Generăm noua parolă hash și actualizăm în baza de date
                new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cursor.execute("UPDATE users SET password_hash = %s, reset_code = NULL WHERE email = %s AND reset_code = %s", (new_password_hash, email, token))
                connection.commit()
                cursor.close()
                connection.close()
                return redirect(url_for('home_page'))
            else:
                cursor.close()
                connection.close()
                return jsonify({"error": "Invalid reset code or email"}), 400
        except psycopg2.Error as e:
            print("Error querying the database for reset password:", e)
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({"error": "Internal server error"}), 500
    else:
        return jsonify({"error": "Failed to connect to database"}), 500

def generate_reset_code():
    return secrets.token_hex(16)


@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = request.form['email']
    new_username = request.form.get('new_username')  # Poate fi opțional
    new_email = request.form.get('new_email')  # Poate fi opțional
    
    connection = get_db_connection()  # Establish connection here
    if connection:
        cursor = connection.cursor()
        try:
            if new_username:
                cursor.execute("UPDATE users SET username = %s WHERE email = %s", (new_username, email))
            if new_email:
                cursor.execute("UPDATE users SET email = %s WHERE email = %s", (new_email, email))
            
            connection.commit()
            cursor.close()
            connection.close()
            return redirect(url_for('home_page'))
            return jsonify({"message": "Profile updated successfully"}), 200
        except Exception as e:
            connection.rollback()
            cursor.close()
            connection.close()
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"error": "Failed to connect to database"}), 500

# Connection string cu datele furnizate
connection_string = "postgresql://neondb_owner:kKfJW6X0pwIG@ep-green-pine-a2y84i42-pooler.eu-central-1.aws.neon.tech/OOP-LAB4?sslmode=require"

if __name__ == "__main__":
    app.run(debug=True)
