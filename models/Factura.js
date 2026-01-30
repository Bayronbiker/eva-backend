const mongoose = require('mongoose');

const FacturaSchema = new mongoose.Schema({
    numero: { type: String, required: true, unique: true },
    clienteId: { type: mongoose.Schema.Types.ObjectId, ref: 'Cliente', required: true },
    clienteNombre: { type: String, required: true },
    fecha: { type: Date, default: Date.now },
    fechaVencimiento: { type: Date },
    subtotal: { type: Number, required: true },
    iva: { type: Number, default: 0 },
    total: { type: Number, required: true },
    estado: { type: String, enum: ['pendiente', 'pagada', 'anulada'], default: 'pendiente' },
    items: [{
        descripcion: String,
        cantidad: Number,
        precioUnitario: Number,
        total: Number
    }],
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Factura', FacturaSchema);