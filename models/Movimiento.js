const mongoose = require('mongoose');

const MovimientoSchema = new mongoose.Schema({
    descripcion: { type: String, required: true },
    monto: { type: Number, required: true },
    tipo: { type: String, enum: ['ingreso', 'gasto'], required: true },
    categoria: { type: String, default: 'General' },
    fecha: { type: Date, default: Date.now },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

module.exports = mongoose.model('Movimiento', MovimientoSchema);