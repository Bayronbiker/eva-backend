const mongoose = require('mongoose');

const CuentaPorPagarSchema = new mongoose.Schema({
  descripcion: { type: String, default: 'Factura' },
  montoTotal:  { type: Number, required: true },
  fecha:       { type: Date, default: Date.now },
  estado:      { type: String, enum: ['pendiente', 'pagada'], default: 'pendiente' }
});

const ProveedorSchema = new mongoose.Schema({
  nombre:             { type: String, required: true },
  nit:                { type: String, default: '' },
  ciudad:             { type: String, default: '' },
  actividadEconomica: { type: String, default: '' },
  telefono:           { type: String, default: '' },
  email:              { type: String, default: '' },
  direccion:          { type: String, default: '' },
  notas:              { type: String, default: '' },
  cuentasPorPagar:    { type: [CuentaPorPagarSchema], default: [] },
  userId:             { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

module.exports = mongoose.model('Proveedor', ProveedorSchema);
