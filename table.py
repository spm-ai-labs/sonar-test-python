from flask import Flask, request, render_template_string
import sqlite3
import logging  # <-- import logging

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cursor.execute('INSERT INTO users (username, password) VALUES ("admin", "admin123")')
    conn.commit()
    return conn

conn = init_db()

# Configurar logging básico
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s %(message)s')

@app.route('/')
def home():
    return '''
        <h1>Inicia sesión</h1>
        <form method="GET" action="/login">
            Usuario: <input type="text" name="username"><br>
            Contraseña: <input type="text" name="password"><br>
            <input type="submit" value="Entrar">
        </form>
    '''

@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')

    # Vulnerabilidad añadida: Logging inseguro de credenciales en texto claro
    logging.info(f'Tentativa de login con usuario: {username}, contraseña: {password}')
    
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return render_template_string(f"<h2>Bienvenido, {username}!</h2>")
    else:
        return "<h2>Credenciales inválidas</h2>"

if __name__ == '__main__':
    app.run(debug=True)
