const mongoose = require('mongoose');

const EmailVerificationSchema = new mongoose.Schema({
    userId:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    email:    { type: String, required: true, lowercase: true, trim: true },
    code:     { type: String, required: true, length: 6 },
    attempts: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now, expires: 600 } // TTL 10 minutos
});

module.exports = mongoose.model('EmailVerification', EmailVerificationSchema);
