require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const EmailVerification = require('./models/EmailVerification');
const PasswordReset = require('./models/PasswordReset');
const { sendVerificationCode, sendPasswordResetCode } = require('./services/email');
const Movimiento = require('./models/Movimiento');
const Factura = require('./models/Factura');
const Remision = require('./models/Remision');
const Cotizacion = require('./models/Cotizacion');
const Cliente = require('./models/Cliente');
const SituacionFinanciera = require('./models/SituacionFinanciera');
const Proveedor = require('./models/Proveedor');
const Inventario = require('./models/Inventario');
const AnthropicPkg = require('@anthropic-ai/sdk');
const Anthropic = AnthropicPkg.default || AnthropicPkg;

const app = express();

const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://eva-web-iota.vercel.app',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
mongoose.set('bufferCommands', false);

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log("✅ Conexión establecida con MongoDB Atlas"))
  .catch(err => console.error("❌ ERROR:", err.message));

// Middleware "laxo": valida JWT pero NO exige email verificado.
// Lo usan los endpoints de /api/auth/email/* (porque el usuario aún no ha verificado).
const verificarTokenSinVerificacion = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: "No se proporcionó token." });
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (e) {
    res.status(403).json({ message: "Sesión expirada o token inválido." });
  }
};

// Middleware "estricto": valida JWT + consulta el User y exige emailVerified=true.
// Si no está verificado responde 403 con { code: 'EMAIL_NOT_VERIFIED' } para que el
// cliente sepa redirigir a la pantalla de verificación.
const verificarToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: "No se proporcionó token." });
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
  } catch (e) {
    return res.status(403).json({ message: "Sesión expirada o token inválido." });
  }
  try {
    const usuario = await User.findById(req.user.id).select('emailVerified email');
    if (!usuario) return res.status(403).json({ message: "Usuario no encontrado" });
    if (!usuario.emailVerified) {
      return res.status(403).json({
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Debes verificar tu correo electrónico para continuar.',
        email: usuario.email || null
      });
    }
    next();
  } catch (err) {
    res.status(500).json({ message: "Error verificando sesión" });
  }
};

// Helper: genera un código de 6 dígitos (incluye ceros a la izquierda).
function generarCodigo6() {
  return String(Math.floor(Math.random() * 1000000)).padStart(6, '0');
}

// Helper: crea un nuevo registro de verificación, eliminando los anteriores del mismo usuario.
// Aplica un rate-limit suave: no permite reenvíos en menos de 60 segundos.
async function crearYEnviarCodigo(usuario, emailDestino) {
  const ultimo = await EmailVerification.findOne({ userId: usuario._id }).sort({ createdAt: -1 });
  if (ultimo) {
    const segs = (Date.now() - ultimo.createdAt.getTime()) / 1000;
    if (segs < 60) {
      const err = new Error(`Espera ${Math.ceil(60 - segs)} segundos antes de solicitar otro código.`);
      err.code = 'RATE_LIMIT';
      err.retryAfter = Math.ceil(60 - segs);
      throw err;
    }
  }
  await EmailVerification.deleteMany({ userId: usuario._id });
  const codigo = generarCodigo6();
  await new EmailVerification({ userId: usuario._id, email: emailDestino, code: codigo }).save();
  await sendVerificationCode(emailDestino, codigo, usuario.nombre);
  return codigo;
}

// AUTH
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, nombre, email, telefono } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Usuario y contraseña son obligatorios" });
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ message: "Debes ingresar un correo electrónico válido" });
    }
    const emailNorm = email.trim().toLowerCase();
    if (await User.findOne({ username })) return res.status(400).json({ message: "El usuario ya existe" });
    if (await User.findOne({ email: emailNorm })) return res.status(400).json({ message: "Ese correo ya está registrado" });
    const passwordHashed = await bcrypt.hash(password, await bcrypt.genSalt(10));
    const nuevoUsuario = await new User({
      username,
      password: passwordHashed,
      nombre: nombre || '',
      email: emailNorm,
      telefono: telefono || '',
      emailVerified: false
    }).save();

    // Token "pendiente": 15 min, marcado con purpose='email-verify'. Solo sirve para los
    // endpoints /api/auth/email/*; cualquier ruta de datos lo rechaza con EMAIL_NOT_VERIFIED.
    const pendingToken = jwt.sign(
      { id: nuevoUsuario._id, username: nuevoUsuario.username, purpose: 'email-verify' },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Disparo del correo en fire-and-forget: si falla, el usuario puede reenviarlo desde
    // la pantalla de verificación con el botón "Reenviar".
    crearYEnviarCodigo(nuevoUsuario, emailNorm).catch(e => console.error('[register] envío código falló:', e.message));

    res.status(201).json({
      message: "Registro exitoso. Te enviamos un código de verificación.",
      pendingToken,
      userId: nuevoUsuario._id,
      email: emailNorm,
      emailVerified: false
    });
  } catch (err) {
    console.error('[register]', err);
    res.status(500).json({ message: "Error en registro" });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (mongoose.connection.readyState !== 1) return res.status(500).json({ message: "Base de datos no disponible" });
    const usuario = await User.findOne({ username });
    if (!usuario) return res.status(400).json({ message: "Usuario no encontrado" });
    if (!await bcrypt.compare(password, usuario.password)) return res.status(400).json({ message: "Contraseña incorrecta" });

    // Si el correo NO está verificado, devolvemos pendingToken y datos mínimos para que el
    // cliente navegue a la pantalla de verificación. Cubre dos casos: (a) usuario que se
    // registró pero no completó la verificación; (b) usuario antiguo sin email/sin verificar.
    if (!usuario.emailVerified) {
      const pendingToken = jwt.sign(
        { id: usuario._id, username: usuario.username, purpose: 'email-verify' },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      // Si ya hay email guardado, dispara el envío del código en background. El rate-limit
      // interno de crearYEnviarCodigo (60s) evita spam si el usuario hace login varias veces.
      if (usuario.email) {
        crearYEnviarCodigo(usuario, usuario.email).catch(e =>
          console.error('[login] envío código en pendingVerification falló:', e.message));
      }
      return res.status(200).json({
        message: "Verificación pendiente",
        pendingVerification: true,
        pendingToken,
        userId: usuario._id,
        username: usuario.username,
        email: usuario.email || null,
        needsEmail: !usuario.email   // true → el cliente debe pedirle el email primero
      });
    }

    // Token completo (30 días) — solo cuando emailVerified=true.
    const token = jwt.sign({ id: usuario._id, username: usuario.username, role: usuario.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ message: "Login exitoso", token, user: { id: usuario._id, username: usuario.username, role: usuario.role || 'user', nombre: usuario.nombre, email: usuario.email } });
  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ message: "Error en login" });
  }
});

// ─── EMAIL VERIFICATION ─────────────────────────────────────────────────────────
// Endpoints autenticados con `verificarTokenSinVerificacion` porque por definición
// el usuario aún no tiene emailVerified=true cuando los llama.

// POST /api/auth/email/send-code
// Body opcional: { email } — solo necesario si el usuario aún no tiene email guardado
// (caso de usuarios antiguos). Si lo manda, se guarda en el User antes de enviar el código.
app.post('/api/auth/email/send-code', verificarTokenSinVerificacion, async (req, res) => {
  try {
    const usuario = await User.findById(req.user.id);
    if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });
    if (usuario.emailVerified) return res.status(400).json({ message: "Tu correo ya está verificado" });

    let emailDestino = usuario.email;
    if (req.body && req.body.email) {
      const e = String(req.body.email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
        return res.status(400).json({ message: "Correo electrónico inválido" });
      }
      // No permitir reusar un email ya verificado por otra cuenta
      const conflicto = await User.findOne({ email: e, _id: { $ne: usuario._id } });
      if (conflicto) return res.status(400).json({ message: "Ese correo ya está registrado por otra cuenta" });
      usuario.email = e;
      await usuario.save();
      emailDestino = e;
    }
    if (!emailDestino) {
      return res.status(400).json({ message: "Debes proporcionar un correo electrónico" });
    }
    await crearYEnviarCodigo(usuario, emailDestino);
    res.json({ message: "Código enviado", email: emailDestino });
  } catch (err) {
    if (err.code === 'RATE_LIMIT') {
      return res.status(429).json({ message: err.message, retryAfter: err.retryAfter });
    }
    console.error('[send-code]', err);
    res.status(500).json({ message: "No se pudo enviar el código. Intenta de nuevo." });
  }
});

// POST /api/auth/email/verify-code
// Body: { code }
app.post('/api/auth/email/verify-code', verificarTokenSinVerificacion, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code || !/^\d{6}$/.test(String(code))) {
      return res.status(400).json({ message: "Código inválido" });
    }
    const ev = await EmailVerification.findOne({ userId: req.user.id });
    if (!ev) return res.status(400).json({ message: "El código expiró. Solicita uno nuevo." });
    if (ev.attempts >= 5) {
      await EmailVerification.deleteMany({ userId: req.user.id });
      return res.status(429).json({ message: "Demasiados intentos. Solicita un código nuevo." });
    }
    if (ev.code !== String(code)) {
      ev.attempts += 1;
      await ev.save();
      const restantes = Math.max(0, 5 - ev.attempts);
      return res.status(400).json({ message: `Código incorrecto. Intentos restantes: ${restantes}` });
    }

    // Éxito: marcar usuario verificado, limpiar registros de verificación, emitir token completo.
    const usuario = await User.findById(req.user.id);
    if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });
    usuario.emailVerified = true;
    usuario.emailVerifiedAt = new Date();
    if (ev.email && usuario.email !== ev.email) usuario.email = ev.email;
    await usuario.save();
    await EmailVerification.deleteMany({ userId: usuario._id });

    const token = jwt.sign(
      { id: usuario._id, username: usuario.username, role: usuario.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    res.json({
      message: "Correo verificado correctamente",
      token,
      user: { id: usuario._id, username: usuario.username, role: usuario.role || 'user', nombre: usuario.nombre, email: usuario.email }
    });
  } catch (err) {
    console.error('[verify-code]', err);
    res.status(500).json({ message: "Error verificando código" });
  }
});

// ─── PASSWORD RESET ─────────────────────────────────────────────────────────────
// Sin autenticación: el usuario está bloqueado fuera. Identificación por username
// o email para soportar usuarios antiguos cuyo username ya es su correo.

// POST /api/auth/password/forgot
// Body: { identifier }  ← username o email del usuario
// Siempre responde 200 con el mismo mensaje (sin importar si el usuario existe o no)
// para evitar enumeración de cuentas. Solo envía el correo si efectivamente existe
// el usuario Y tiene un email guardado a donde mandar el código.
app.post('/api/auth/password/forgot', async (req, res) => {
  const respuestaGenerica = {
    message: "Si la cuenta existe y tiene un correo asociado, te enviaremos un código."
  };
  try {
    const { identifier } = req.body || {};
    if (!identifier || typeof identifier !== 'string') {
      return res.status(200).json(respuestaGenerica);
    }
    const input = identifier.trim();
    const usuario = await User.findOne({
      $or: [{ username: input }, { email: input.toLowerCase() }]
    });
    // Si no existe o no tiene email, devolvemos la misma respuesta genérica.
    if (!usuario || !usuario.email) {
      return res.status(200).json(respuestaGenerica);
    }

    // Rate-limit suave: si ya hay un código activo creado hace <60s, no enviamos otro.
    const ultimo = await PasswordReset.findOne({ userId: usuario._id }).sort({ createdAt: -1 });
    if (ultimo) {
      const segs = (Date.now() - ultimo.createdAt.getTime()) / 1000;
      if (segs < 60) {
        return res.status(200).json(respuestaGenerica);   // silencioso para no revelar nada
      }
    }
    await PasswordReset.deleteMany({ userId: usuario._id });
    const codigo = generarCodigo6();
    await new PasswordReset({ userId: usuario._id, email: usuario.email, code: codigo }).save();
    sendPasswordResetCode(usuario.email, codigo, usuario.nombre)
      .catch(e => console.error('[forgot-password] envío falló:', e.message));

    return res.status(200).json(respuestaGenerica);
  } catch (err) {
    console.error('[forgot-password]', err);
    // Aún en error interno devolvemos el mensaje genérico para no filtrar nada.
    return res.status(200).json(respuestaGenerica);
  }
});

// POST /api/auth/password/reset
// Body: { identifier, code, newPassword }
// Valida el código, actualiza la contraseña (hasheada), elimina los códigos del usuario
// y devuelve un token de sesión completo para que el usuario quede logueado.
app.post('/api/auth/password/reset', async (req, res) => {
  try {
    const { identifier, code, newPassword } = req.body || {};
    if (!identifier || !code || !newPassword) {
      return res.status(400).json({ message: "Faltan datos: identifier, code y newPassword son obligatorios." });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 7) {
      return res.status(400).json({ message: "La nueva contraseña debe tener al menos 7 caracteres." });
    }
    if (!/^\d{6}$/.test(String(code))) {
      return res.status(400).json({ message: "Código inválido" });
    }

    const input = String(identifier).trim();
    const usuario = await User.findOne({
      $or: [{ username: input }, { email: input.toLowerCase() }]
    });
    if (!usuario) {
      return res.status(400).json({ message: "Código inválido o expirado" });
    }
    const pr = await PasswordReset.findOne({ userId: usuario._id });
    if (!pr) {
      return res.status(400).json({ message: "El código expiró. Solicita uno nuevo." });
    }
    if (pr.attempts >= 5) {
      await PasswordReset.deleteMany({ userId: usuario._id });
      return res.status(429).json({ message: "Demasiados intentos. Solicita un código nuevo." });
    }
    if (pr.code !== String(code)) {
      pr.attempts += 1;
      await pr.save();
      const restantes = Math.max(0, 5 - pr.attempts);
      return res.status(400).json({ message: `Código incorrecto. Intentos restantes: ${restantes}` });
    }

    // Éxito: actualizar contraseña + limpiar códigos + emitir token de sesión.
    usuario.password = await bcrypt.hash(newPassword, await bcrypt.genSalt(10));
    // Si al resetear queremos también marcar el email como verificado (recibió el código,
    // luego el correo es válido y accesible), descomenta las dos líneas siguientes.
    // Por ahora respetamos el estado anterior para no mezclar flujos.
    // if (!usuario.emailVerified) { usuario.emailVerified = true; usuario.emailVerifiedAt = new Date(); }
    await usuario.save();
    await PasswordReset.deleteMany({ userId: usuario._id });

    // Solo emitimos token completo si el correo ya estaba verificado. Si no, devolvemos
    // pendingToken para que pase por el flujo de verificación (consistente con login).
    if (usuario.emailVerified) {
      const token = jwt.sign(
        { id: usuario._id, username: usuario.username, role: usuario.role },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
      );
      return res.json({
        message: "Contraseña actualizada",
        token,
        user: { id: usuario._id, username: usuario.username, role: usuario.role || 'user', nombre: usuario.nombre, email: usuario.email }
      });
    } else {
      const pendingToken = jwt.sign(
        { id: usuario._id, username: usuario.username, purpose: 'email-verify' },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      return res.json({
        message: "Contraseña actualizada. Verifica tu correo para continuar.",
        pendingVerification: true,
        pendingToken,
        userId: usuario._id,
        username: usuario.username,
        email: usuario.email,
        needsEmail: false
      });
    }
  } catch (err) {
    console.error('[reset-password]', err);
    res.status(500).json({ message: "Error restableciendo contraseña" });
  }
});

app.get('/api/user/profile', verificarToken, async (req, res) => {
  try {
    res.json(await User.findById(req.user.id).select('-password'));
  } catch (err) { res.status(500).json({ message: "Error en perfil" }); }
});

// MOVIMIENTOS
app.get('/api/movimientos', verificarToken, async (req, res) => {
  try {
    res.json(await Movimiento.find({ userId: req.user.id }).sort({ fecha: -1 }));
  } catch (err) { res.status(500).json({ message: "Error obteniendo movimientos" }); }
});

app.get('/api/movimientos/:id', verificarToken, async (req, res) => {
  try {
    const m = await Movimiento.findOne({ _id: req.params.id, userId: req.user.id });
    if (!m) return res.status(404).json({ message: "Movimiento no encontrado" });
    res.json(m);
  } catch (err) { res.status(500).json({ message: "Error obteniendo movimiento" }); }
});

app.post('/api/movimientos', verificarToken, async (req, res) => {
  try {
    const { descripcion, monto, tipo, categoria, fecha, proveedor, metodoPago } = req.body;
    if (!monto || !tipo || !categoria) return res.status(400).json({ message: "Faltan campos obligatorios" });
    if (!['ingreso', 'gasto'].includes(tipo)) return res.status(400).json({ message: "Tipo de movimiento inválido" });
    const movimiento = await new Movimiento({
      descripcion: descripcion || categoria,
      monto,
      tipo,
      categoria,
      fecha: fecha ? new Date(fecha) : Date.now(),
      userId: req.user.id,
      proveedor: proveedor || '',
      metodoPago: metodoPago || ''
    }).save();
    res.status(201).json({ message: "Movimiento creado", movimiento });
  } catch (err) { res.status(500).json({ message: "Error creando movimiento" }); }
});

app.put('/api/movimientos/:id', verificarToken, async (req, res) => {
  try {
    const { descripcion, monto, tipo, categoria, fecha, proveedor, metodoPago } = req.body;
    const m = await Movimiento.findOneAndUpdate({ _id: req.params.id, userId: req.user.id },
      { descripcion, monto, tipo, categoria, fecha: fecha ? new Date(fecha) : Date.now(), proveedor, metodoPago },
      { new: true });
    if (!m) return res.status(404).json({ message: "Movimiento no encontrado" });
    res.json({ message: "Movimiento actualizado", movimiento: m });
  } catch (err) { res.status(500).json({ message: "Error actualizando movimiento" }); }
});

app.delete('/api/movimientos/:id', verificarToken, async (req, res) => {
  try {
    const m = await Movimiento.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!m) return res.status(404).json({ message: "Movimiento no encontrado" });
    res.json({ message: "Movimiento eliminado" });
  } catch (err) { res.status(500).json({ message: "Error eliminando movimiento" }); }
});

app.get('/api/resumen', verificarToken, async (req, res) => {
  try {
    const movimientos = await Movimiento.find({ userId: req.user.id });
    let ingresos = 0, gastos = 0;
    movimientos.forEach(m => m.tipo === 'ingreso' ? ingresos += m.monto : gastos += m.monto);
    res.json({ saldo: ingresos - gastos, ingresos, gastos });
  } catch (err) { res.status(500).json({ message: "Error en resumen" }); }
});

// CLIENTES
app.get('/api/clientes', verificarToken, async (req, res) => {
  try { res.json(await Cliente.find({ userId: req.user.id }).sort({ nombre: 1 })); }
  catch (err) { res.status(500).json({ message: "Error obteniendo clientes" }); }
});

app.get('/api/clientes/:id', verificarToken, async (req, res) => {
  try {
    const c = await Cliente.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json(c);
  } catch (err) { res.status(500).json({ message: "Error obteniendo cliente" }); }
});

app.post('/api/clientes', verificarToken, async (req, res) => {
  try {
    const { nombre, nit, telefono, email, direccion, tipo, ciudad, actividadEconomica } = req.body;
    if (!nombre || !nit) return res.status(400).json({ message: "Nombre y NIT son obligatorios" });
    if (await Cliente.findOne({ nit, userId: req.user.id })) return res.status(400).json({ message: "Ya existe un cliente con ese NIT" });
    const cliente = await new Cliente({ nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, tipo, userId: req.user.id }).save();
    res.status(201).json({ message: "Cliente creado", cliente });
  } catch (err) { res.status(500).json({ message: "Error creando cliente" }); }
});

app.put('/api/clientes/:id', verificarToken, async (req, res) => {
  try {
    const { nombre, nit, telefono, email, direccion, tipo, ciudad, actividadEconomica } = req.body;
    const c = await Cliente.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, tipo }, { new: true });
    if (!c) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json({ message: "Cliente actualizado", cliente: c });
  } catch (err) { res.status(500).json({ message: "Error actualizando cliente" }); }
});

app.delete('/api/clientes/:id', verificarToken, async (req, res) => {
  try {
    const c = await Cliente.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: "Cliente no encontrado" });
    res.json({ message: "Cliente eliminado" });
  } catch (err) { res.status(500).json({ message: "Error eliminando cliente" }); }
});

// FACTURAS
app.get('/api/facturas', verificarToken, async (req, res) => {
  try {
    const filtro = { userId: req.user.id };
    if (req.query.estado) filtro.estado = req.query.estado;
    res.json(await Factura.find(filtro).sort({ fecha: -1 }));
  } catch (err) { res.status(500).json({ message: "Error obteniendo facturas" }); }
});

app.get('/api/facturas/:id', verificarToken, async (req, res) => {
  try {
    const f = await Factura.findOne({ _id: req.params.id, userId: req.user.id });
    if (!f) return res.status(404).json({ message: "Factura no encontrada" });
    res.json(f);
  } catch (err) { res.status(500).json({ message: "Error obteniendo factura" }); }
});

app.post('/api/facturas', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, items } = req.body;
    if (!numero || !clienteNombre || subtotal === undefined || total === undefined) return res.status(400).json({ message: "Faltan campos obligatorios" });
    if (await Factura.findOne({ numero, userId: req.user.id })) return res.status(400).json({ message: "Ya existe una factura con ese número" });
    const factura = await new Factura({ numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, items, userId: req.user.id }).save();
    res.status(201).json({ message: "Factura creada", factura });
  } catch (err) { res.status(500).json({ message: "Error creando factura" }); }
});

app.put('/api/facturas/:id', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, estado, items } = req.body;
    const f = await Factura.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, estado, items }, { new: true });
    if (!f) return res.status(404).json({ message: "Factura no encontrada" });
    res.json({ message: "Factura actualizada", factura: f });
  } catch (err) { res.status(500).json({ message: "Error actualizando factura" }); }
});

app.patch('/api/facturas/:id/estado', verificarToken, async (req, res) => {
  try {
    const { estado } = req.body;
    if (!['pendiente', 'pagada', 'anulada'].includes(estado)) return res.status(400).json({ message: "Estado no válido" });
    const f = await Factura.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { estado }, { new: true });
    if (!f) return res.status(404).json({ message: "Factura no encontrada" });
    res.json({ message: "Estado actualizado", factura: f });
  } catch (err) { res.status(500).json({ message: "Error actualizando estado" }); }
});

app.delete('/api/facturas/:id', verificarToken, async (req, res) => {
  try {
    const f = await Factura.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!f) return res.status(404).json({ message: "Factura no encontrada" });
    res.json({ message: "Factura eliminada" });
  } catch (err) { res.status(500).json({ message: "Error eliminando factura" }); }
});

// REMISIONES
app.get('/api/remisiones', verificarToken, async (req, res) => {
  try {
    const filtro = { userId: req.user.id };
    if (req.query.estado) filtro.estado = req.query.estado;
    res.json(await Remision.find(filtro).sort({ fecha: -1 }));
  } catch (err) { res.status(500).json({ message: "Error obteniendo remisiones" }); }
});

app.get('/api/remisiones/:id', verificarToken, async (req, res) => {
  try {
    const r = await Remision.findOne({ _id: req.params.id, userId: req.user.id });
    if (!r) return res.status(404).json({ message: "Remisión no encontrada" });
    res.json(r);
  } catch (err) { res.status(500).json({ message: "Error obteniendo remisión" }); }
});

app.post('/api/remisiones', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, direccionEntrega, items } = req.body;
    if (!numero || !clienteNombre) return res.status(400).json({ message: "Número y cliente son obligatorios" });
    if (await Remision.findOne({ numero, userId: req.user.id })) return res.status(400).json({ message: "Ya existe una remisión con ese número" });
    const remision = await new Remision({ numero, clienteId, clienteNombre, direccionEntrega, items, userId: req.user.id }).save();
    res.status(201).json({ message: "Remisión creada", remision });
  } catch (err) { res.status(500).json({ message: "Error creando remisión" }); }
});

app.put('/api/remisiones/:id', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, direccionEntrega, estado, items } = req.body;
    const r = await Remision.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { numero, clienteId, clienteNombre, direccionEntrega, estado, items }, { new: true });
    if (!r) return res.status(404).json({ message: "Remisión no encontrada" });
    res.json({ message: "Remisión actualizada", remision: r });
  } catch (err) { res.status(500).json({ message: "Error actualizando remisión" }); }
});

app.patch('/api/remisiones/:id/estado', verificarToken, async (req, res) => {
  try {
    const { estado } = req.body;
    if (!['pendiente', 'entregada', 'anulada'].includes(estado)) return res.status(400).json({ message: "Estado no válido" });
    const r = await Remision.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { estado }, { new: true });
    if (!r) return res.status(404).json({ message: "Remisión no encontrada" });
    res.json({ message: "Estado actualizado", remision: r });
  } catch (err) { res.status(500).json({ message: "Error actualizando estado" }); }
});

app.delete('/api/remisiones/:id', verificarToken, async (req, res) => {
  try {
    const r = await Remision.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!r) return res.status(404).json({ message: "Remisión no encontrada" });
    res.json({ message: "Remisión eliminada" });
  } catch (err) { res.status(500).json({ message: "Error eliminando remisión" }); }
});

// COTIZACIONES
app.get('/api/cotizaciones', verificarToken, async (req, res) => {
  try {
    const filtro = { userId: req.user.id };
    if (req.query.estado) filtro.estado = req.query.estado;
    res.json(await Cotizacion.find(filtro).sort({ fecha: -1 }));
  } catch (err) { res.status(500).json({ message: "Error obteniendo cotizaciones" }); }
});

app.get('/api/cotizaciones/:id', verificarToken, async (req, res) => {
  try {
    const c = await Cotizacion.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: "Cotización no encontrada" });
    res.json(c);
  } catch (err) { res.status(500).json({ message: "Error obteniendo cotización" }); }
});

app.post('/api/cotizaciones', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, validez, subtotal, iva, total, items } = req.body;
    if (!numero || !clienteNombre || subtotal === undefined || total === undefined) return res.status(400).json({ message: "Faltan campos obligatorios" });
    if (await Cotizacion.findOne({ numero, userId: req.user.id })) return res.status(400).json({ message: "Ya existe una cotización con ese número" });
    const cotizacion = await new Cotizacion({ numero, clienteId, clienteNombre, validez, subtotal, iva, total, items, userId: req.user.id }).save();
    res.status(201).json({ message: "Cotización creada", cotizacion });
  } catch (err) { res.status(500).json({ message: "Error creando cotización" }); }
});

app.put('/api/cotizaciones/:id', verificarToken, async (req, res) => {
  try {
    const { numero, clienteId, clienteNombre, validez, subtotal, iva, total, estado, items } = req.body;
    const c = await Cotizacion.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { numero, clienteId, clienteNombre, validez, subtotal, iva, total, estado, items }, { new: true });
    if (!c) return res.status(404).json({ message: "Cotización no encontrada" });
    res.json({ message: "Cotización actualizada", cotizacion: c });
  } catch (err) { res.status(500).json({ message: "Error actualizando cotización" }); }
});

app.patch('/api/cotizaciones/:id/estado', verificarToken, async (req, res) => {
  try {
    const { estado } = req.body;
    if (!['pendiente', 'aprobada', 'rechazada', 'convertida'].includes(estado)) return res.status(400).json({ message: "Estado no válido" });
    const c = await Cotizacion.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { estado }, { new: true });
    if (!c) return res.status(404).json({ message: "Cotización no encontrada" });
    res.json({ message: "Estado actualizado", cotizacion: c });
  } catch (err) { res.status(500).json({ message: "Error actualizando estado" }); }
});

app.post('/api/cotizaciones/:id/convertir', verificarToken, async (req, res) => {
  try {
    const cotizacion = await Cotizacion.findOne({ _id: req.params.id, userId: req.user.id });
    if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
    if (cotizacion.estado === 'convertida') return res.status(400).json({ message: "Ya fue convertida" });
    const { numeroFactura, fechaVencimiento } = req.body;
    if (!numeroFactura) return res.status(400).json({ message: "Indica el número de factura" });
    const factura = await new Factura({ numero: numeroFactura, clienteId: cotizacion.clienteId, clienteNombre: cotizacion.clienteNombre, fechaVencimiento, subtotal: cotizacion.subtotal, iva: cotizacion.iva, total: cotizacion.total, items: cotizacion.items, userId: req.user.id }).save();
    cotizacion.estado = 'convertida';
    await cotizacion.save();
    res.status(201).json({ message: "Convertida en factura", factura });
  } catch (err) { res.status(500).json({ message: "Error convirtiendo cotización" }); }
});

app.delete('/api/cotizaciones/:id', verificarToken, async (req, res) => {
  try {
    const c = await Cotizacion.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: "Cotización no encontrada" });
    res.json({ message: "Cotización eliminada" });
  } catch (err) { res.status(500).json({ message: "Error eliminando cotización" }); }
});

// ─── Situación Financiera ────────────────────────────────────────────────────

// GET — Obtiene (o crea vacío) el documento de situación financiera del usuario
app.get('/api/situacion-financiera', verificarToken, async (req, res) => {
  try {
    let sf = await SituacionFinanciera.findOne({ userId: req.user.id });
    if (!sf) {
      sf = await new SituacionFinanciera({ userId: req.user.id }).save();
    }
    res.json(sf);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo situación financiera' });
  }
});

// PUT — Upsert completo del documento de situación financiera
app.put('/api/situacion-financiera', verificarToken, async (req, res) => {
  try {
    const { efectivo, otrosActivos, activosFijos, otrosPasivos, obligacionesBancos } = req.body;
    const sf = await SituacionFinanciera.findOneAndUpdate(
      { userId: req.user.id },
      { efectivo, otrosActivos, activosFijos, otrosPasivos, obligacionesBancos },
      { new: true, upsert: true, runValidators: true }
    );
    res.json(sf);
  } catch (err) {
    res.status(500).json({ message: 'Error guardando situación financiera' });
  }
});

// ─── Proveedores ─────────────────────────────────────────────────────────────

app.get('/api/proveedores', verificarToken, async (req, res) => {
  try {
    const proveedores = await Proveedor.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(proveedores);
  } catch (err) {
    res.status(500).json({ message: 'Error obteniendo proveedores' });
  }
});

app.post('/api/proveedores', verificarToken, async (req, res) => {
  try {
    const { nombre, nit, telefono, email, direccion, notas } = req.body;
    if (!nombre?.trim()) return res.status(400).json({ message: 'El nombre es requerido' });
    const proveedor = await new Proveedor({ userId: req.user.id, nombre, nit, telefono, email, direccion, notas }).save();
    res.status(201).json(proveedor);
  } catch (err) {
    res.status(500).json({ message: 'Error creando proveedor' });
  }
});

app.put('/api/proveedores/:id', verificarToken, async (req, res) => {
  try {
    const { nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, notas } = req.body;
    const proveedor = await Proveedor.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, notas },
      { new: true, runValidators: true }
    );
    if (!proveedor) return res.status(404).json({ message: 'Proveedor no encontrado' });
    res.json(proveedor);
  } catch (err) {
    res.status(500).json({ message: 'Error actualizando proveedor' });
  }
});

app.delete('/api/proveedores/:id', verificarToken, async (req, res) => {
  try {
    const p = await Proveedor.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!p) return res.status(404).json({ message: 'Proveedor no encontrado' });
    res.json({ message: 'Proveedor eliminado' });
  } catch (err) {
    res.status(500).json({ message: 'Error eliminando proveedor' });
  }
});

// ─── Inventario ───────────────────────────────────────────────────────────────

app.get('/api/inventario', verificarToken, async (req, res) => {
  try {
    const items = await Inventario.find({ userId: req.user.id }).sort({ createdAt: -1 });
    res.json(items);
  } catch (err) { res.status(500).json({ message: 'Error obteniendo inventario' }); }
});

app.post('/api/inventario', verificarToken, async (req, res) => {
  try {
    const { nombre, cantidad, precioCompra, precioVenta, categoria, descripcion, foto } = req.body;
    if (!nombre?.trim()) return res.status(400).json({ message: 'El nombre es requerido' });
    const item = await new Inventario({ nombre, cantidad, precioCompra, precioVenta, categoria, descripcion, foto, userId: req.user.id }).save();
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ message: 'Error creando producto' }); }
});

app.put('/api/inventario/:id', verificarToken, async (req, res) => {
  try {
    const { nombre, cantidad, precioCompra, precioVenta, categoria, descripcion, foto } = req.body;
    const item = await Inventario.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { nombre, cantidad, precioCompra, precioVenta, categoria, descripcion, foto },
      { new: true, runValidators: true }
    );
    if (!item) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json(item);
  } catch (err) { res.status(500).json({ message: 'Error actualizando producto' }); }
});

app.delete('/api/inventario/:id', verificarToken, async (req, res) => {
  try {
    const item = await Inventario.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!item) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ message: 'Producto eliminado' });
  } catch (err) { res.status(500).json({ message: 'Error eliminando producto' }); }
});

// ─── Cuentas por pagar (sub-recursos del Proveedor) ───────────────────────────

app.post('/api/proveedores/:id/cuentas-pagar', verificarToken, async (req, res) => {
  try {
    const { descripcion, montoTotal, fecha } = req.body;
    if (!montoTotal) return res.status(400).json({ message: 'El monto es requerido' });
    const prov = await Proveedor.findOne({ _id: req.params.id, userId: req.user.id });
    if (!prov) return res.status(404).json({ message: 'Proveedor no encontrado' });
    prov.cuentasPorPagar.push({ descripcion, montoTotal, fecha: fecha ? new Date(fecha) : new Date() });
    await prov.save();
    res.status(201).json(prov);
  } catch (err) { res.status(500).json({ message: 'Error agregando cuenta por pagar' }); }
});

app.put('/api/proveedores/:id/cuentas-pagar/:cuentaId', verificarToken, async (req, res) => {
  try {
    const { estado, descripcion, montoTotal } = req.body;
    const prov = await Proveedor.findOne({ _id: req.params.id, userId: req.user.id });
    if (!prov) return res.status(404).json({ message: 'Proveedor no encontrado' });
    const cuenta = prov.cuentasPorPagar.id(req.params.cuentaId);
    if (!cuenta) return res.status(404).json({ message: 'Cuenta no encontrada' });
    if (estado)      cuenta.estado      = estado;
    if (descripcion) cuenta.descripcion = descripcion;
    if (montoTotal)  cuenta.montoTotal  = montoTotal;
    await prov.save();
    res.json(prov);
  } catch (err) { res.status(500).json({ message: 'Error actualizando cuenta' }); }
});

app.delete('/api/proveedores/:id/cuentas-pagar/:cuentaId', verificarToken, async (req, res) => {
  try {
    const prov = await Proveedor.findOne({ _id: req.params.id, userId: req.user.id });
    if (!prov) return res.status(404).json({ message: 'Proveedor no encontrado' });
    prov.cuentasPorPagar.pull({ _id: req.params.cuentaId });
    await prov.save();
    res.json(prov);
  } catch (err) { res.status(500).json({ message: 'Error eliminando cuenta' }); }
});

// ─── Análisis de factura con IA (Claude Vision) ───────────────────────────────

app.post('/api/analizar-factura', verificarToken, async (req, res) => {
  try {
    const { imagen } = req.body;
    if (!imagen) return res.status(400).json({ message: 'Imagen requerida' });

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey || apiKey === 'TU_API_KEY_AQUI') {
      return res.status(503).json({ message: 'API key de Anthropic no configurada. Agrégala en el archivo .env del servidor.' });
    }

    const client = new Anthropic({ apiKey });

    // Extraer base64 limpio y tipo de media
    const base64 = imagen.includes(',') ? imagen.split(',')[1] : imagen;
    const mediaType = imagen.includes('image/png') ? 'image/png'
                    : imagen.includes('image/webp') ? 'image/webp'
                    : 'image/jpeg';

    const message = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1500,
      messages: [{
        role: 'user',
        content: [
          {
            type: 'image',
            source: { type: 'base64', media_type: mediaType, data: base64 }
          },
          {
            type: 'text',
            text: `Eres un asistente de contabilidad. Analiza esta imagen de factura o documento comercial y extrae toda la información posible.

Responde ÚNICAMENTE con un JSON válido con esta estructura exacta (sin texto adicional antes o después):

{
  "proveedor": {
    "nombre": "razón social o nombre de quien EMITE la factura",
    "nit": "NIT o cédula del emisor",
    "ciudad": "ciudad del emisor",
    "telefono": "teléfono del emisor",
    "email": "email del emisor",
    "direccion": "dirección del emisor",
    "actividadEconomica": "actividad económica o tipo de negocio"
  },
  "productos": [
    {
      "nombre": "nombre del producto o servicio",
      "cantidad": 1,
      "precioUnitario": 0,
      "precioTotal": 0
    }
  ],
  "totalFactura": 0,
  "fechaFactura": "YYYY-MM-DD",
  "numeroFactura": "número de factura si está disponible"
}

Reglas:
- Para campos de texto no encontrados usa null
- Para campos numéricos no encontrados usa 0
- Los precios deben ser números sin símbolos ni separadores de miles
- La fecha debe estar en formato YYYY-MM-DD, si no hay fecha usa null
- Extrae TODOS los productos o servicios que aparezcan en la factura`
          }
        ]
      }]
    });

    const texto = message.content[0].text.trim();
    // Extraer JSON aunque haya texto extra alrededor
    const jsonMatch = texto.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return res.status(422).json({ message: 'No se pudo extraer información estructurada de la imagen. Asegúrate de que sea una factura clara.' });
    }

    const datos = JSON.parse(jsonMatch[0]);

    // ── MEJORA #2: Normalizar precios formato colombiano ──────────────────
    const normPrecio = (val) => {
      if (!val && val !== 0) return 0;
      if (typeof val === 'number' && !isNaN(val)) return Math.round(Math.abs(val));
      let s = String(val).replace(/[$COP\s%+]/gi, '').trim();
      if (!s) return 0;
      // Si tiene punto Y coma → el último es el decimal
      if (s.includes('.') && s.includes(',')) {
        if (s.lastIndexOf(',') > s.lastIndexOf('.')) {
          s = s.replace(/\./g, '').replace(',', '.'); // "1.500,50" → "1500.50"
        } else {
          s = s.replace(/,/g, '');                    // "1,500.50" → "1500.50"
        }
      } else if (s.includes('.')) {
        const partes = s.split('.');
        // Separador de miles si hay más de 1 punto o parte decimal de 3 cifras
        if (partes.length > 2 || (partes.length === 2 && partes[1].length === 3)) {
          s = s.replace(/\./g, '');                   // "1.500.000" → "1500000"
        }
      } else if (s.includes(',')) {
        const partes = s.split(',');
        if (partes.length > 2 || (partes.length === 2 && partes[1].length === 3)) {
          s = s.replace(/,/g, '');                    // "1,500,000" → "1500000"
        } else {
          s = s.replace(',', '.');                    // "1500,50"  → "1500.50"
        }
      }
      const n = parseFloat(s);
      return isNaN(n) ? 0 : Math.round(Math.abs(n));
    };

    // ── MEJORA #6: Limpiar NIT ────────────────────────────────────────────
    const normNIT = (nit) => {
      if (!nit) return '';
      let s = String(nit).replace(/[^0-9-]/g, '');
      // Quitar dígito verificador (últimos 2 chars si son -X)
      const m = s.match(/^(\d+)-?\d$/);
      if (m) s = m[1];
      return s.replace(/-/g, ''); // quitar guiones restantes
    };

    // Aplicar normalización
    datos.totalFactura = normPrecio(datos.totalFactura);
    if (Array.isArray(datos.productos)) {
      datos.productos = datos.productos.map(p => ({
        ...p,
        nombre:         p.nombre || '',
        cantidad:       Math.max(1, Math.round(Math.abs(Number(p.cantidad) || 1))),
        precioUnitario: normPrecio(p.precioUnitario),
        precioTotal:    normPrecio(p.precioTotal),
      }));
    }
    if (datos.proveedor) {
      datos.proveedor.nit = normNIT(datos.proveedor.nit);
    }

    res.json(datos);
  } catch (err) {
    console.error('Error analizando factura:', err);
    const msg = err?.error?.error?.message || err?.message || 'Error desconocido';
    if (err.status === 400) return res.status(400).json({ message: 'La IA no pudo procesar la imagen: ' + msg });
    if (err.status === 401) return res.status(401).json({ message: 'API key de Anthropic inválida. Verifica la variable ANTHROPIC_API_KEY en Railway.' });
    if (err.status === 404) return res.status(400).json({ message: 'Modelo de IA no encontrado: ' + msg });
    if (err.status === 529 || err.status === 503) return res.status(503).json({ message: 'La API de Anthropic está sobrecargada. Intenta en unos segundos.' });
    res.status(500).json({ message: 'Error al analizar la factura: ' + msg });
  }
});

// ─── Chat con IA (Asistente EVA) ─────────────────────────────────────────────

// ─── Herramientas (tool use) que EVA puede invocar ───────────────────────────
// Cada herramienta es una función que el modelo puede pedir ejecutar. El backend
// la corre con seguridad (scope userId, validación) y devuelve el resultado.
const EVA_TOOLS = [
  {
    name: 'consultar_movimientos',
    description: 'Consulta los gastos e ingresos del usuario con filtros opcionales (rango de fechas, tipo, categoría). Úsala para preguntas tipo "¿cuánto gasté en combustible este mes?", "muéstrame mis últimos ingresos", "¿qué movimientos tengo de la semana pasada?".',
    input_schema: {
      type: 'object',
      properties: {
        desde: { type: 'string', description: 'Fecha de inicio en formato YYYY-MM-DD. Opcional. Si se omite, usa los últimos 30 días.' },
        hasta: { type: 'string', description: 'Fecha final (inclusive) en formato YYYY-MM-DD. Opcional. Si se omite, usa hoy.' },
        tipo: { type: 'string', enum: ['ingreso', 'gasto'], description: 'Filtra por tipo. Omite para ver ambos.' },
        categoria: { type: 'string', description: 'Filtra por categoría exacta (ej. "Comida", "Combustible", "Servicios"). Opcional.' },
        limite: { type: 'integer', description: 'Máximo de movimientos. Por defecto 20, máximo 100.' }
      }
    }
  },
  {
    name: 'consultar_facturas',
    description: 'Consulta las facturas del usuario, opcionalmente filtradas por estado o cliente. Úsala para "¿qué facturas tengo pendientes?", "¿quién me debe?", "facturas de María Gómez".',
    input_schema: {
      type: 'object',
      properties: {
        estado: { type: 'string', enum: ['pendiente', 'pagada', 'anulada'], description: 'Filtra por estado. Omite para ver todas.' },
        cliente: { type: 'string', description: 'Nombre del cliente (búsqueda parcial, no distingue mayúsculas). Opcional.' },
        limite: { type: 'integer', description: 'Máximo de facturas. Por defecto 20.' }
      }
    }
  },
  {
    name: 'consultar_proveedor',
    description: 'Busca un proveedor por su nombre (búsqueda parcial). Devuelve datos de contacto y NIT.',
    input_schema: {
      type: 'object',
      properties: {
        nombre: { type: 'string', description: 'Nombre o parte del nombre del proveedor.' }
      },
      required: ['nombre']
    }
  },
  {
    name: 'consultar_cliente',
    description: 'Busca un cliente por su nombre (búsqueda parcial). Devuelve datos de contacto y NIT.',
    input_schema: {
      type: 'object',
      properties: {
        nombre: { type: 'string', description: 'Nombre o parte del nombre del cliente.' }
      },
      required: ['nombre']
    }
  },
  {
    name: 'resumen_periodo',
    description: 'Devuelve el resumen financiero (total ingresos, gastos, saldo, número de movimientos) de un periodo. Úsala para "¿cómo me fue este mes?", "¿cuál fue mi mejor semana?".',
    input_schema: {
      type: 'object',
      properties: {
        desde: { type: 'string', description: 'Inicio del periodo en YYYY-MM-DD.' },
        hasta: { type: 'string', description: 'Fin del periodo en YYYY-MM-DD.' }
      },
      required: ['desde', 'hasta']
    }
  },
  {
    name: 'crear_movimiento',
    description: 'Crea un nuevo gasto o ingreso. SIEMPRE confirma con el usuario el monto, tipo y categoría ANTES de llamar esta herramienta — repite los datos en lenguaje natural y pregunta "¿lo registro?".',
    input_schema: {
      type: 'object',
      properties: {
        tipo: { type: 'string', enum: ['ingreso', 'gasto'] },
        monto: { type: 'number', description: 'Valor en pesos colombianos (entero positivo).' },
        categoria: { type: 'string', description: 'Categoría (ej. "Comida", "Servicios", "Venta de productos").' },
        descripcion: { type: 'string', description: 'Descripción libre. Opcional.' },
        fecha: { type: 'string', description: 'Fecha del movimiento en YYYY-MM-DD. Si se omite, usa hoy.' },
        proveedor: { type: 'string', description: 'Proveedor o fuente. Opcional.' },
        metodoPago: { type: 'string', description: 'Efectivo, Tarjeta, Transferencia, Nequi, Daviplata, Otro. Opcional.' }
      },
      required: ['tipo', 'monto', 'categoria']
    }
  },
  {
    name: 'crear_proveedor',
    description: 'Registra un nuevo proveedor. SIEMPRE confirma con el usuario el nombre y NIT antes de llamar.',
    input_schema: {
      type: 'object',
      properties: {
        nombre: { type: 'string' },
        nit: { type: 'string', description: 'NIT o cédula sin puntos. Opcional.' },
        telefono: { type: 'string', description: 'Opcional.' },
        email: { type: 'string', description: 'Opcional.' },
        direccion: { type: 'string', description: 'Opcional.' }
      },
      required: ['nombre']
    }
  },
  {
    name: 'marcar_factura',
    description: 'Cambia el estado de una factura (pendiente, pagada, anulada). Recibe el número de factura o el ID interno. SIEMPRE confirma con el usuario antes de marcar como pagada o anulada.',
    input_schema: {
      type: 'object',
      properties: {
        numero: { type: 'string', description: 'Número de factura (ej. "FAC-001") o el ID interno de MongoDB.' },
        estado: { type: 'string', enum: ['pendiente', 'pagada', 'anulada'] }
      },
      required: ['numero', 'estado']
    },
    // Cache breakpoint en el último tool → todo el bloque de tools entra al caché.
    cache_control: { type: 'ephemeral' }
  },
  {
    name: 'top_categorias_gasto',
    description: 'Devuelve las categorías donde el usuario más gastó en un periodo, ordenadas. Úsala para "¿en qué se me va más la plata?", "mis mayores gastos del mes".',
    input_schema: {
      type: 'object',
      properties: {
        desde: { type: 'string', description: 'Inicio del periodo en YYYY-MM-DD.' },
        hasta: { type: 'string', description: 'Fin del periodo en YYYY-MM-DD.' },
        limite: { type: 'integer', description: 'Top N categorías. Por defecto 5, máximo 20.' }
      },
      required: ['desde', 'hasta']
    }
  }
];

// Helpers de fecha y normalización
function _parseFecha(s, fallback) {
  if (!s) return fallback;
  const d = new Date(s);
  return isNaN(d.getTime()) ? fallback : d;
}
function _finDelDia(d) {
  const x = new Date(d); x.setHours(23, 59, 59, 999); return x;
}
function _isoDia(d) {
  return new Date(d).toISOString().substring(0, 10);
}

// Ejecuta la herramienta solicitada, siempre con scope al userId del usuario.
async function ejecutarHerramientaEva(name, input, userId) {
  try {
    switch (name) {
      case 'consultar_movimientos': {
        const hasta = _finDelDia(_parseFecha(input.hasta, new Date()));
        const desde = _parseFecha(input.desde, new Date(Date.now() - 30 * 24 * 60 * 60 * 1000));
        const q = { userId, fecha: { $gte: desde, $lte: hasta } };
        if (input.tipo) q.tipo = input.tipo;
        if (input.categoria) q.categoria = input.categoria;
        const limite = Math.min(input.limite || 20, 100);
        const movs = await Movimiento.find(q).sort({ fecha: -1 }).limit(limite).lean();
        const total = movs.reduce((s, m) => s + (m.monto || 0), 0);
        return {
          cantidad: movs.length,
          totalSumado: total,
          movimientos: movs.map(m => ({
            fecha: _isoDia(m.fecha),
            tipo: m.tipo,
            categoria: m.categoria,
            monto: m.monto,
            descripcion: m.descripcion,
            proveedor: m.proveedor || undefined,
            metodoPago: m.metodoPago || undefined
          }))
        };
      }
      case 'consultar_facturas': {
        const q = { userId };
        if (input.estado) q.estado = input.estado;
        if (input.cliente) q.clienteNombre = { $regex: input.cliente, $options: 'i' };
        const limite = Math.min(input.limite || 20, 100);
        const facts = await Factura.find(q).sort({ fecha: -1 }).limit(limite).lean();
        return {
          cantidad: facts.length,
          totalSumado: facts.reduce((s, f) => s + (f.total || 0), 0),
          facturas: facts.map(f => ({
            numero: f.numero,
            cliente: f.clienteNombre,
            fecha: f.fecha ? _isoDia(f.fecha) : undefined,
            estado: f.estado,
            total: f.total
          }))
        };
      }
      case 'consultar_proveedor': {
        if (!input.nombre?.trim()) return { error: 'El nombre es requerido' };
        const provs = await Proveedor.find({
          userId, nombre: { $regex: input.nombre.trim(), $options: 'i' }
        }).limit(5).lean();
        return {
          encontrados: provs.length,
          proveedores: provs.map(p => ({
            nombre: p.nombre, nit: p.nit, telefono: p.telefono, email: p.email, ciudad: p.ciudad
          }))
        };
      }
      case 'consultar_cliente': {
        if (!input.nombre?.trim()) return { error: 'El nombre es requerido' };
        const cls = await Cliente.find({
          userId, nombre: { $regex: input.nombre.trim(), $options: 'i' }
        }).limit(5).lean();
        return {
          encontrados: cls.length,
          clientes: cls.map(c => ({
            nombre: c.nombre, nit: c.nit, telefono: c.telefono, email: c.email, ciudad: c.ciudad
          }))
        };
      }
      case 'resumen_periodo': {
        const desde = _parseFecha(input.desde);
        const hasta = _parseFecha(input.hasta);
        if (!desde || !hasta) return { error: 'Fechas inválidas; usa formato YYYY-MM-DD' };
        const hastaFin = _finDelDia(hasta);
        const movs = await Movimiento.find({ userId, fecha: { $gte: desde, $lte: hastaFin } }).lean();
        const ingresos = movs.filter(m => m.tipo === 'ingreso').reduce((s, m) => s + (m.monto || 0), 0);
        const gastos = movs.filter(m => m.tipo === 'gasto').reduce((s, m) => s + (m.monto || 0), 0);
        return {
          desde: _isoDia(desde),
          hasta: _isoDia(hasta),
          ingresos, gastos, saldo: ingresos - gastos,
          cantidadMovimientos: movs.length
        };
      }
      case 'crear_movimiento': {
        const { tipo, monto, categoria, descripcion, fecha, proveedor, metodoPago } = input;
        if (!['ingreso', 'gasto'].includes(tipo)) return { error: 'tipo debe ser "ingreso" o "gasto"' };
        if (!monto || monto <= 0) return { error: 'monto debe ser un número positivo' };
        if (!categoria?.trim()) return { error: 'categoria es requerida' };
        const mov = await new Movimiento({
          descripcion: descripcion || categoria,
          monto, tipo, categoria,
          fecha: fecha ? new Date(fecha) : Date.now(),
          userId,
          proveedor: proveedor || '',
          metodoPago: metodoPago || ''
        }).save();
        return { ok: true, id: mov._id.toString(), mensaje: `${tipo === 'ingreso' ? 'Ingreso' : 'Gasto'} de $${monto} en "${categoria}" registrado correctamente.` };
      }
      case 'crear_proveedor': {
        if (!input.nombre?.trim()) return { error: 'nombre es requerido' };
        const p = await new Proveedor({
          userId,
          nombre: input.nombre.trim(),
          nit: input.nit || '',
          telefono: input.telefono || '',
          email: input.email || '',
          direccion: input.direccion || ''
        }).save();
        return { ok: true, id: p._id.toString(), mensaje: `Proveedor "${p.nombre}" creado.` };
      }
      case 'marcar_factura': {
        if (!['pendiente', 'pagada', 'anulada'].includes(input.estado)) return { error: 'estado inválido' };
        let f = null;
        if (mongoose.Types.ObjectId.isValid(input.numero)) {
          f = await Factura.findOneAndUpdate({ _id: input.numero, userId }, { estado: input.estado }, { new: true });
        }
        if (!f) {
          f = await Factura.findOneAndUpdate({ numero: input.numero, userId }, { estado: input.estado }, { new: true });
        }
        if (!f) return { error: `Factura "${input.numero}" no encontrada` };
        return { ok: true, numero: f.numero, estado: f.estado, mensaje: `Factura ${f.numero} marcada como ${f.estado}.` };
      }
      case 'top_categorias_gasto': {
        const desde = _parseFecha(input.desde);
        const hasta = _parseFecha(input.hasta);
        if (!desde || !hasta) return { error: 'Fechas inválidas; usa YYYY-MM-DD' };
        const hastaFin = _finDelDia(hasta);
        const limite = Math.min(input.limite || 5, 20);
        const result = await Movimiento.aggregate([
          { $match: {
              userId: new mongoose.Types.ObjectId(userId),
              tipo: 'gasto',
              fecha: { $gte: desde, $lte: hastaFin }
          } },
          { $group: { _id: '$categoria', total: { $sum: '$monto' }, cantidad: { $sum: 1 } } },
          { $sort: { total: -1 } },
          { $limit: limite }
        ]);
        return {
          desde: _isoDia(desde),
          hasta: _isoDia(hasta),
          categorias: result.map(r => ({ categoria: r._id, total: r.total, cantidad: r.cantidad }))
        };
      }
      default:
        return { error: 'Herramienta desconocida: ' + name };
    }
  } catch (e) {
    console.error(`Tool "${name}" error:`, e?.message);
    return { error: e?.message || 'Error al ejecutar la herramienta' };
  }
}

app.post('/api/chat', verificarToken, async (req, res) => {
  try {
    const { messages } = req.body;
    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ message: 'Se requiere un array de mensajes.' });
    }

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey || apiKey === 'TU_API_KEY_AQUI') {
      return res.status(503).json({ message: 'API key de Anthropic no configurada.' });
    }
    const client = new Anthropic({ apiKey });

    // ─── System prompt ESTÁTICO (cacheable con prompt caching) ────────────────
    // Contiene el conocimiento concreto y permanente de la app EVA: rutas, pantallas,
    // contabilidad colombiana, tono. Igual en cada llamada → Anthropic lo cachea y
    // las siguientes peticiones pagan ~10% del costo de entrada por leerlo.
    const SYSTEM_BASE = `Eres EVA, la asistente inteligente de la app "EVA Finanzas", una plataforma de gestión para pequeñas y medianas empresas colombianas. Hablas con el dueño del negocio. Tu trabajo es ayudarle a usar la app y a entender sus finanzas, contabilidad e impuestos en Colombia.

## CÓMO ESTÁ ORGANIZADA LA APP

La barra inferior tiene 4 pestañas:
- **Inicio**: pantalla principal con accesos rápidos.
- **Balance**: con dos sub-pestañas:
  - "Caja Menor": ingresos y gastos del día seleccionado. Abajo hay dos botones: **+ Nuevo Ingreso** (verde) y **+ Nuevo Gasto** (rojo). El selector de día (LUN–DOM) está arriba.
  - "Situación Financiera": activos, pasivos, obligaciones bancarias.
- **Cuentas**: cuentas por cobrar y por pagar (facturas pendientes, deudas).
- **Inventario**: productos. Incluye el botón **"Escanear factura con IA"** (la cámara extrae proveedor, productos y total de una foto).

El **menú lateral ☰** (esquina superior izquierda) da acceso a: Facturas, Cotizaciones, Remisiones, Clientes, Proveedores, Inventario, Balance, Estadísticas, Contactos, Centro de Ayuda, Configuración y Cerrar Sesión.

Arriba a la derecha hay ⚙ (configuración) y 🔔 (notificaciones).

## RUTAS PASO A PASO PARA LAS TAREAS MÁS COMUNES

**Registrar un gasto:** Balance → "Caja Menor" → botón **+ Nuevo Gasto** → elige Tipo (Pagado / Deuda) → llena Fecha, Valor, Categoría (Servicios, Compras, Arriendo, Nómina, Mercadeo, etc.), Proveedor (puedes elegir uno existente o tocar **"Crear nuevo proveedor"** al final del desplegable), Método de pago, Descripción → **Registrar gasto**.

**Registrar un ingreso:** Balance → **+ Nuevo Ingreso** → Fecha, Valor, Categoría (Venta de productos, Prestación de servicios, Factura cobrada, Anticipo, etc.), Proveedor / Fuente (lista real con opción de crear), Método de pago, Descripción → **Registrar ingreso**.

**Crear una factura:** Menú ☰ → Facturas → **+ Nueva factura** → elige cliente (o crea uno nuevo desde ahí), agrega items (descripción, cantidad, precio), revisa IVA y total → guardar. La factura nace en estado "pendiente".

**Marcar factura como pagada / anulada:** Facturas → abre la factura → cambia estado.

**Convertir una cotización en factura:** Menú ☰ → Cotizaciones → abre la cotización → **"Convertir a factura"** → indica número de factura → queda creada automáticamente.

**Crear cliente o proveedor:** Menú ☰ → Clientes / Proveedores → **+ Nuevo**. También puedes crear un proveedor sobre la marcha desde el desplegable "Proveedor" en Nuevo Gasto / Nuevo Ingreso.

**Escanear una factura física con IA:** Inventario → **"Escanear factura"** → toma foto → la IA extrae proveedor, productos y total → confirmas y se crean el proveedor y los productos automáticamente.

**Ver el resumen financiero:** Balance → "Situación Financiera" (activos, pasivos, obligaciones bancarias).

**Estadísticas:** Menú ☰ → Estadísticas (gráficos de ingresos vs gastos, categorías, etc.).

## CONTABILIDAD E IMPUESTOS EN COLOMBIA

Eres precisa con: IVA (19% general, 5% para algunos bienes, exentos), retención en la fuente, régimen simple vs. ordinario, NIT y dígito de verificación, RUT, facturación electrónica DIAN, ICA municipal, ReteIVA, ReteICA, declaración de renta, libros contables. Cuando una cifra dependa del año fiscal o de la actividad económica, dilo y sugiere consultar a un contador.

## TONO Y ESTILO

- Respondes SIEMPRE en español, cercano y respetuoso (sin tutear a las patadas, sin "amigo/parce" excesivo).
- Vas al grano. Usa **negrita** para los pasos clave, listas numeradas para procesos, viñetas para opciones.
- Cuando expliques "cómo hacer X en EVA", da la ruta exacta (las de arriba). NO digas "no tengo claridad sobre tu versión" ni "revisa el menú": tienes claro lo de arriba.
- Si te preguntan algo que claramente no existe en EVA, dilo con honestidad y sugiere la alternativa más cercana.
- Nunca inventes datos del usuario. Si los necesitas, mira la sección "Datos en vivo" más abajo o pídelos.
- Usa el nombre del usuario cuando esté disponible.
- Cifras en pesos colombianos con separador de miles (ej. $ 1.250.000).`;

    // ─── Contexto EN VIVO del usuario (no se cachea — cambia por usuario) ─────
    // Le permite a EVA responder "¿cuál es mi saldo?", "¿cuántas facturas tengo
    // pendientes?", "¿quién me debe más?", con números reales.
    let contextoVivo = '';
    try {
      const userId = req.user.id;
      const [user, movs, facturasPend, clientesN, proveedoresN, inventarioN] = await Promise.all([
        User.findById(userId).select('nombre username').lean(),
        Movimiento.find({ userId }).sort({ fecha: -1 }).limit(50).lean(),
        Factura.find({ userId, estado: 'pendiente' }).select('total clienteNombre numero').lean(),
        Cliente.countDocuments({ userId }),
        Proveedor.countDocuments({ userId }),
        Inventario.countDocuments({ userId })
      ]);

      const ingresos = movs.filter(m => m.tipo === 'ingreso').reduce((s, m) => s + (m.monto || 0), 0);
      const gastos   = movs.filter(m => m.tipo === 'gasto').reduce((s, m) => s + (m.monto || 0), 0);
      const saldo    = ingresos - gastos;
      const totalPendiente = facturasPend.reduce((s, f) => s + (f.total || 0), 0);

      const fmt = n => '$ ' + Math.round(n || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.');
      const ultimos = movs.slice(0, 5).map(m => {
        const signo = m.tipo === 'ingreso' ? '+' : '-';
        const fecha = new Date(m.fecha).toLocaleDateString('es-CO');
        const desc  = m.descripcion ? ' · ' + m.descripcion : '';
        return `  - ${signo}${fmt(m.monto)} · ${m.categoria}${desc} (${fecha})`;
      }).join('\n') || '  (aún sin movimientos registrados)';

      const nombre = user?.nombre?.trim() || user?.username || 'usuario';

      contextoVivo = `## DATOS EN VIVO DEL USUARIO (úsalos para responder con cifras REALES)

Usuario: ${nombre}
Saldo (últimos 50 movimientos): ${fmt(saldo)}  (ingresos ${fmt(ingresos)} − gastos ${fmt(gastos)})
Facturas pendientes: ${facturasPend.length}  ·  total por cobrar: ${fmt(totalPendiente)}
Clientes registrados: ${clientesN}  ·  Proveedores: ${proveedoresN}  ·  Productos en inventario: ${inventarioN}

Últimos movimientos:
${ultimos}

Reglas:
- Si te preguntan por saldo, facturas pendientes, cuántos clientes/proveedores tiene, sus últimos movimientos, etc., RESPONDE con estos números.
- Si te piden detalle que no aparece aquí (un cliente específico, una factura puntual, un producto), dile a qué pantalla ir a consultarlo.
- Si todo está en cero, díselo con tacto y sugiere qué registrar primero para empezar.`;
    } catch (e) {
      console.error('chat: error armando contexto en vivo:', e?.message);
      // Si falla la carga de contexto, igual respondemos (sin datos en vivo).
    }

    // ── Loop de ejecución de herramientas ─────────────────────────────────────
    // El modelo puede pedir invocar una o varias herramientas (consultar datos,
    // crear movimientos, etc.). Las corremos, devolvemos el resultado y
    // repetimos hasta que el modelo dé la respuesta final (stop_reason !== 'tool_use').
    let currentMessages = messages;
    let finalText = '';
    const MAX_ITER = 5;  // tope de seguridad: nunca más de 5 vueltas por mensaje

    for (let iter = 0; iter < MAX_ITER; iter++) {
      const response = await client.messages.create({
        model: 'claude-haiku-4-5-20251001',  // Haiku: rápido y barato; suficiente para esta etapa
        max_tokens: 2048,
        system: [
          // Parte estática (prompt + persona + rutas) → cacheada 5 min.
          { type: 'text', text: SYSTEM_BASE, cache_control: { type: 'ephemeral' } },
          // Parte dinámica (cifras del usuario) → no se cachea.
          ...(contextoVivo ? [{ type: 'text', text: contextoVivo }] : [])
        ],
        tools: EVA_TOOLS,
        messages: currentMessages,
      });

      // Acumula el texto que EVA quiso decir antes/después de invocar tools.
      const textBlocks = response.content.filter(b => b.type === 'text');
      if (textBlocks.length) {
        const t = textBlocks.map(b => b.text).join('\n').trim();
        if (t) finalText += (finalText ? '\n\n' : '') + t;
      }

      if (response.stop_reason !== 'tool_use') break;

      // El modelo pidió ejecutar una o varias herramientas
      const toolUses = response.content.filter(b => b.type === 'tool_use');
      const toolResults = await Promise.all(toolUses.map(async tu => ({
        type: 'tool_result',
        tool_use_id: tu.id,
        content: JSON.stringify(await ejecutarHerramientaEva(tu.name, tu.input, req.user.id))
      })));

      currentMessages = [
        ...currentMessages,
        { role: 'assistant', content: response.content },
        { role: 'user', content: toolResults }
      ];
    }

    res.json({ reply: finalText || 'Sin respuesta.' });

  } catch (err) {
    console.error('Error en chat EVA:', err);
    const msg = err?.error?.error?.message || err?.message || 'Error desconocido';
    if (err.status === 401) return res.status(401).json({ message: 'API key de Anthropic inválida.' });
    if (err.status === 529 || err.status === 503) return res.status(503).json({ message: 'La IA está sobrecargada. Intenta en unos segundos.' });
    res.status(500).json({ message: 'Error en el chat: ' + msg });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Servidor EVA activo en puerto ${PORT}`));