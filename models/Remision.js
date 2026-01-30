const mongoose = require('mongoose');

const RemisionSchema = new mongoose.Schema({
    numero: { type: String, required: true, unique: true },
    clienteId: { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente' },
    clienteNombre: { type: String, required: true },
    fecha: { type: Date, default: Date.now },
    direccionEntrega: { type: String },
    estado: { type: String, enum: ['pendiente', 'entregada', 'anulada'], default: 'pendiente' },
    items: [{
        descripcion: String,
        cantidad: Number,
        precioUnitario: Number,
        total: Number
    }],
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Remision', RemisionSchema);