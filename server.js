// server.js - Aplicación de gestión de usuarios y contenido

const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const lodash = require('lodash');
const mysql = require('mysql');
const util = require('util');
const fs = require('fs');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());

// 1. Configuración insegura de la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // Contraseña vacía
  database: 'userdb'
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to database');
});

// 2. Clave secreta JWT hardcodeada y débil
const JWT_SECRET = 'secretkey123';

// 3. Almacenamiento de tokens en memoria (podría ser un problema de escalado y seguridad)
const activeTokens = {};

// 4. Función vulnerable a inyección SQL
function getUser(username, callback) {
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  db.query(query, (err, result) => {
    if (err) return callback(err);
    callback(null, result[0]);
  });
}

// 5. Función de login con problemas de seguridad
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // 6. Validación insuficiente de entrada
  if (!username || !password) {
    return res.status(400).send('Username and password required');
  }

  // 7. Consulta SQL vulnerable
  getUser(username, (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Database error');
    }

    // 8. Comparación de contraseñas insegura (tiempo constante)
    if (user && user.password === password) {
      // 9. Información sensible en el token
      const token = jwt.sign({ 
        userId: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        // 10. Incluyendo datos sensibles innecesarios
        email: user.email,
        createdAt: user.createdAt
      }, JWT_SECRET, { expiresIn: '24h' });

      activeTokens[user.id] = token;
      
      // 11. Configuración insegura de cookies
      res.cookie('session', token, { 
        httpOnly: false, // Debería ser true
        secure: false,    // Debería ser true en producción
        sameSite: 'none'
      });
      
      return res.json({ token });
    }
    
    res.status(401).send('Invalid credentials');
  });
});

// 12. Middleware de autenticación con verificación débil
function authenticate(req, res, next) {
  const token = req.cookies.session || req.headers.authorization;
  
  if (!token) {
    return res.status(401).send('Authentication required');
  }

  try {
    // 13. No verificar la firma correctamente
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    
    // 14. No verificar si el token está en la lista de revocados
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
}

// 15. Ruta con posible XSS almacenado
app.post('/posts', authenticate, (req, res) => {
  const { title, content } = req.body;
  
  // 16. Escapado insuficiente de contenido HTML
  const sanitizedContent = content.replace(/<script>/g, '');
  
  const query = 'INSERT INTO posts (title, content, author_id) VALUES (?, ?, ?)';
  db.query(query, [title, sanitizedContent, req.user.userId], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error creating post');
    }
    res.send('Post created');
  });
});

// 17. Ruta vulnerable a XSS reflejado
app.get('/search', (req, res) => {
  const { q } = req.query;
  
  // 18. No escapado de entrada del usuario
  res.send(`<h1>Results for: ${q}</h1><p>No results found</p>`);
});

// 19. Ruta con información sensible expuesta
app.get('/user/:id', authenticate, (req, res) => {
  const userId = req.params.id;
  
  // 20. Falta de control de acceso adecuado
  const query = 'SELECT id, username, email, isAdmin FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err || !results.length) {
      return res.status(404).send('User not found');
    }
    
    // 21. Exponiendo información sensible sin necesidad
    res.json(results[0]);
  });
});

// 22. Ruta vulnerable a inyección de prototipos
app.post('/clone', (req, res) => {
  const { object } = req.body;
  
  // 23. Clonado inseguro de objetos
  const cloned = lodash.cloneDeep(object);
  
  // 24. Modificación peligrosa del prototipo
  if (cloned.isAdmin && typeof cloned.isAdmin === 'boolean') {
    Object.prototype.isAdmin = cloned.isAdmin;
  }
  
  res.json({ success: true });
});

// 25. Ruta con descarga de archivos insegura
app.get('/download', (req, res) => {
  const { file } = req.query;
  
  // 26. Validación insuficiente de la ruta del archivo
  if (!file || typeof file !== 'string') {
    return res.status(400).send('Invalid file');
  }
  
  // 27. Path traversal posible
  const filePath = `./uploads/${file}`;
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    
    // 28. Cabeceras inseguras para descarga
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(data);
  });
});

// 29. Ruta con procesamiento XML inseguro
app.post('/parse-xml', (req, res) => {
  const { xml } = req.body;
  
  // 30. No deshabilitar entidades externas
  const parser = new (require('xml2js').Parser)({
    explicitArray: false,
    mergeAttrs: true
  });
  
  parser.parseString(xml, (err, result) => {
    if (err) {
      return res.status(400).send('Invalid XML');
    }
    
    // 31. Procesamiento inseguro del resultado
    res.json(result);
  });
});

// 32. Función con posible ReDoS
function validateInput(input) {
  // 33. Expresión regular vulnerable
  const regex = /^([a-zA-Z0-9]+([\s-]?[a-zA-Z0-9]+)*)+$/;
  return regex.test(input);
}

// 34. Ruta con validación vulnerable
app.post('/validate', (req, res) => {
  const { input } = req.body;
  
  if (validateInput(input)) {
    res.send('Valid input');
  } else {
    res.status(400).send('Invalid input');
  }
});

// 35. Manejo inseguro de errores
app.use((err, req, res, next) => {
  // 36. Exposición de detalles del error
  console.error(err.stack);
  res.status(500).send(`Error: ${err.message}`);
});

// 37. Configuración de cabeceras inseguras
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '0'); // Deshabilitando protección XSS
  next();
});

// 38. Función con problema de race condition
let counter = 0;
app.get('/increment', (req, res) => {
  counter++;
  res.send(`Counter: ${counter}`);
});

// 39. Función con gestión de memoria insegura
const largeBufferCache = {};
app.get('/cache-buffer', (req, res) => {
  const { id } = req.query;
  
  if (!largeBufferCache[id]) {
    // 40. Creación de buffer grande sin límite
    largeBufferCache[id] = Buffer.alloc(1024 * 1024 * 100); // 100MB
  }
  
  res.send('Buffer cached');
});

// 41. Ruta con serialización insegura
app.get('/serialize', (req, res) => {
  const user = {
    username: 'admin',
    // 42. Función en objeto serializado
    toString: () => { console.log('Sensitive data leaked!'); return ''; }
  };
  
  res.json(user);
});

// 43. Función con manipulación de objetos peligrosa
function mergeUserData(user, input) {
  // 44. Asignación de propiedades sin validación
  for (const key in input) {
    user[key] = input[key];
  }
  return user;
}

// 45. Ruta con problema de CSRF
app.post('/change-email', authenticate, (req, res) => {
  const { newEmail } = req.body;
  
  // 46. Falta de token CSRF
  const query = 'UPDATE users SET email = ? WHERE id = ?';
  db.query(query, [newEmail, req.user.userId], (err) => {
    if (err) {
      return res.status(500).send('Error updating email');
    }
    res.send('Email updated');
  });
});

// 47. Función con vulnerabilidad de tiempo
function checkApiKey(apiKey) {
  const validKey = 'SECURE_API_KEY_123';
  
  // 48. Comparación que depende del tamaño de la entrada
  for (let i = 0; i < apiKey.length; i++) {
    if (apiKey[i] !== validKey[i]) {
      return false;
    }
  }
  
  return apiKey.length === validKey.length;
}

// 49. Ruta con validación de API key vulnerable
app.get('/sensitive-data', (req, res) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!checkApiKey(apiKey)) {
    return res.status(403).send('Invalid API key');
  }
  
  res.json({ data: 'Very sensitive information' });
});

// 50. Función con problema de recursión infinita
function deepClone(obj, depth = 0) {
  if (depth > 100) return obj; // Límite insuficiente
  
  const clone = {};
  for (const key in obj) {
    clone[key] = typeof obj[key] === 'object' ? deepClone(obj[key], depth + 1) : obj[key];
  }
  return clone;
}

// 51. Ruta con posible DoS por recursión
app.post('/deep-clone', (req, res) => {
  const { data } = req.body;
  const cloned = deepClone(data);
  res.json(cloned);
});

// 52. Función con gestión de promesas insegura
async function processUserData(userId) {
  const query = util.promisify(db.query).bind(db);
  
  try {
    const user = await query('SELECT * FROM users WHERE id = ?', [userId]);
    const posts = await query('SELECT * FROM posts WHERE author_id = ?', [userId]);
    
    // 53. No manejar adecuadamente el rechazo de promesas
    return { user, posts };
  } catch (err) {
    console.error(err);
    throw err;
  }
}

// 54. Ruta con manejo asíncrono inseguro
app.get('/user-data/:id', async (req, res) => {
  try {
    const data = await processUserData(req.params.id);
    res.json(data);
  } catch (err) {
    res.status(500).send('Error processing request');
  }
});

// 55. Función con problema de bloqueo de evento loop
function expensiveOperation() {
  const start = Date.now();
  
  // 56. Operación síncrona costosa
  while (Date.now() - start < 5000) {
    // Simular procesamiento pesado
    Math.sqrt(Math.random());
  }
  
  return 'Done';
}

// 57. Ruta con operación bloqueante
app.get('/expensive', (req, res) => {
  const result = expensiveOperation();
  res.send(result);
});

// 58. Función con gestión de caché insegura
const cache = {};
function getCachedData(key) {
  // 59. No limpiar la caché periódicamente
  if (cache[key]) {
    return cache[key];
  }
  
  const data = `Data for ${key}`;
  cache[key] = data;
  return data;
}

// 60. Ruta con posible memory leak
app.get('/cached/:key', (req, res) => {
  const data = getCachedData(req.params.key);
  res.send(data);
});

// 61. Función con problema de hashing inseguro
function hashPassword(password) {
  // 62. Hashing inseguro sin salt
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    hash = ((hash << 5) - hash) + password.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  return hash.toString();
}

// 63. Ruta con registro inseguro
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  
  if (!username || !password || !email) {
    return res.status(400).send('All fields are required');
  }
  
  // 64. Almacenamiento de contraseña con hash inseguro
  const hashedPassword = hashPassword(password);
  
  const query = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
  db.query(query, [username, hashedPassword, email], (err) => {
    if (err) {
      return res.status(500).send('Error creating user');
    }
    res.send('User created');
  });
});

// 65. Función con problema de concurrencia
let accountBalance = 1000;
app.post('/transfer', authenticate, (req, res) => {
  const { amount, toUserId } = req.body;
  
  // 66. Operación no atómica sobre recurso compartido
  if (accountBalance >= amount) {
    // Simular procesamiento
    setTimeout(() => {
      accountBalance -= amount;
      res.send(`Transferred ${amount}. New balance: ${accountBalance}`);
    }, 100);
  } else {
    res.status(400).send('Insufficient funds');
  }
});

// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
