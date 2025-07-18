from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Crear base de datos en memoria con una tabla simple
def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    cursor.execute('INSERT INTO users (username, password) VALUES ("admin", "admin123")')
    conn.commit()
    return conn

conn = init_db()

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

    cursor = conn.cursor()

    # Vulnerabilidad: inyección SQL por concatenar directamente inputs sin sanitizar
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        # Vulnerabilidad XSS: se muestra directamente el nombre del usuario sin escapar
        return render_template_string(f"<h2>Bienvenido, {username}!</h2>")
    else:
        return "<h2>Credenciales inválidas</h2>"

if __name__ == '__main__':
    app.run(debug=True)
