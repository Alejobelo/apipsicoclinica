const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
app.use(cors())
const JWT_SECRET = 'supersecreto';

app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  database: 'mi_basededatos',
});

db.connect((err) => {
  if (err) {
    console.error('Error de conexión a la base de datos: ' + err);
    return;
  }
  console.log('Conexión a la base de datos exitosa');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Consulta la base de datos para encontrar al usuario por correo electrónico
  const sql = 'SELECT id, email, password FROM usuarios WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Error al buscar el usuario: ' + err);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Correo electrónico o contraseña incorrectos' });
    }

    const user = results[0];

    // Compara la contraseña ingresada con la contraseña almacenada
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ message: 'Correo electrónico o contraseña incorrectos' });
      }

      // Crea un token JWT y lo envía en la respuesta
      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
      res.json({ token });
    });
  });
});

app.post('/register', (req, res) => {
  const { email, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error('Error al encriptar la contraseña: ' + err);
      res.status(500).json({ error: 'Error al crear el usuario' });
      return;
    }

    const query = 'INSERT INTO usuarios (email, password) VALUES (?, ?)';
    db.query(query, [email, hash], (err, result) => {
      if (err) {
        console.error('Error al agregar usuario: ' + err);
        res.status(500).json({ error: 'Error al agregar usuario' });
        return;
      }
      res.status(201).json({ message: 'Usuario agregado correctamente' });
    });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Consulta la base de datos para encontrar al usuario por correo electrónico
  const sql = 'SELECT id, email, password FROM usuarios WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error('Error al buscar el usuario: ' + err);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Correo electrónico o contraseña incorrectos' });
    }

    const user = results[0];

    // Compara la contraseña ingresada con la contraseña almacenada
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ message: 'Correo electrónico o contraseña incorrectos' });
      }

      // Crea un token JWT y lo envía en la respuesta
      const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET);
      res.json({ token });
    });
  });
});
app.listen(port, () => {
  console.log(`Servidor API corriendo en http://localhost:${port}`);
});