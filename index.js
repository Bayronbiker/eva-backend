require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const Movimiento = require('./models/Movimiento');
const Factura = require('./models/Factura');
const Remision = require('./models/Remision');
const Cotizacion = require('./models/Cotizacion');
const Cliente = require('./models/Cliente');

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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
mongoose.set('bufferCommands', false);

mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 })
  .then(() => console.log("✅ Conexión establecida con MongoDB Atlas"))
  .catch(err => console.error("❌ ERROR:", err.message));

const verificarToken = (req, res, next) => {
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

// AUTH
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, nombre, email, telefono } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Usuario y contraseña son obligatorios" });
    if (await User.findOne({ username })) return res.status(400).json({ message: "El usuario ya existe" });
    const passwordHashed = await bcrypt.hash(password, await bcrypt.genSalt(10));
    await new User({ username, password: passwordHashed, nombre: nombre || '', email: email || '', telefono: telefono || '' }).save();
    res.status(201).json({ message: "Registro exitoso" });
  } catch (err) { res.status(500).json({ message: "Error en registro" }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (mongoose.connection.readyState !== 1) return res.status(500).json({ message: "Base de datos no disponible" });
    const usuario = await User.findOne({ username });
    if (!usuario) return res.status(400).json({ message: "Usuario no encontrado" });
    if (!await bcrypt.compare(password, usuario.password)) return res.status(400).json({ message: "Contraseña incorrecta" });
    const token = jwt.sign({ id: usuario._id, username: usuario.username, role: usuario.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ message: "Login exitoso", token, user: { id: usuario._id, username: usuario.username, role: usuario.role || 'user', nombre: usuario.nombre, email: usuario.email } });
  } catch (err) { res.status(500).json({ message: "Error en login" }); }
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Servidor EVA activo en puerto ${PORT}`));