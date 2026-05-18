const mongoose = require('mongoose');

const ProveedorSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  nombre:    { type: String, required: true },
  nit:       { type: String, default: '' },
  telefono:  { type: String, default: '' },
  email:     { type: String, default: '' },
  direccion: { type: String, default: '' },
  notas:     { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.model('Proveedor', ProveedorSchema);
