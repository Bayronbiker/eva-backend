const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'contador', 'user'], default: 'user' },
    nombre: { type: String },
    email: { type: String, lowercase: true, trim: true },
    telefono: { type: String },
    emailVerified: { type: Boolean, default: false },
    emailVerifiedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

// Índice único parcial sobre email: solo enforza unicidad cuando es un string no vacío,
// permitiendo que usuarios antiguos con email '' o null sigan coexistiendo sin colisionar.
UserSchema.index(
    { email: 1 },
    { unique: true, partialFilterExpression: { email: { $type: 'string', $gt: '' } } }
);

module.exports = mongoose.model('User', UserSchema);
