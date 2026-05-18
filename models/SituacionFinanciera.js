const mongoose = require('mongoose');

const ActivoFijoSchema = new mongoose.Schema({
  nombre:      { type: String, required: true },
  descripcion: { type: String, default: '' },
  precio:      { type: Number, required: true, default: 0 }
});

const ObligacionBancariaSchema = new mongoose.Schema({
  fechaDesembolso: { type: Date,   default: Date.now },
  nombreBanco:     { type: String, required: true },
  valorTotal:      { type: Number, required: true, default: 0 },
  numeroCuotas:    { type: Number, required: true, default: 1 },
  valorAPagar:     { type: Number, required: true, default: 0 }
});

const SituacionFinancieraSchema = new mongoose.Schema({
  userId:              { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  efectivo:            { type: Number, default: 0 },
  otrosActivos:        { type: Number, default: 0 },
  activosFijos:        { type: [ActivoFijoSchema], default: [] },
  otrosPasivos:        { type: Number, default: 0 },
  obligacionesBancos:  { type: [ObligacionBancariaSchema], default: [] }
}, { timestamps: true });

module.exports = mongoose.model('SituacionFinanciera', SituacionFinancieraSchema);
