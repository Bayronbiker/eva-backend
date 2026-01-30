const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

// --- 1. Middlewares ---
app.use(cors({
  origin: '*', // En desarrollo puedes usar '*' para permitir todo
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Permite que el servidor entienda datos en formato JSON

// --- 2. Conexión a MongoDB Atlas ---
// La URL real la pondremos en el archivo .env después
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/eva_db';

mongoose.connect(mongoURI)
    .then(() => console.log('✅ Conectado a MongoDB exitosamente'))
    .catch(err => console.error('❌ Error al conectar a MongoDB:', err));

// --- 3. Rutas de prueba ---
app.get('/', (req, res) => {
    res.send('🚀 El servidor de EVA está funcionando correctamente');
});

// --- 4. Encendido del Servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`📡 Servidor corriendo en http://localhost:${PORT}`);
});
