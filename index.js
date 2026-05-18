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

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`🚀 Servidor EVA activo en puerto ${PORT}`));