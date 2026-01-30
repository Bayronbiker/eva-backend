const mongoose = require('mongoose');

const ClienteSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    nit: { type: String, required: true, unique: true },
    telefono: { type: String },
    email: { type: String },
    direccion: { type: String },
    tipo: { type: String, enum: ['natural', 'juridico'], default: 'natural' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Cliente', ClienteSchema);