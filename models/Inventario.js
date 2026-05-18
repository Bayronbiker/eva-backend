const mongoose = require('mongoose');

const InventarioSchema = new mongoose.Schema({
  nombre:      { type: String, required: true },
  cantidad:    { type: Number, required: true, default: 0 },
  precioCompra:{ type: Number, default: 0 },
  precioVenta: { type: Number, default: 0 },
  categoria:   { type: String, default: 'Otros' },
  descripcion: { type: String, default: '' },
  foto:        { type: String, default: '' },   // base64 o URL
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

module.exports = mongoose.model('Inventario', InventarioSchema);
