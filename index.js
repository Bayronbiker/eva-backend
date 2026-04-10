require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// --- MODELOS ---
const User = require('./models/User');
const Movimiento = require('./models/Movimiento');
const Factura = require('./models/Factura');
const Remision = require('./models/Remision');
const Cotizacion = require('./models/Cotizacion');
const Cliente = require('./models/Cliente');

const app = express();

// --- CONFIGURACIÓN DE CORS ---
// Lista de orígenes permitidos (agrega aquí tu dominio de Vercel)
const ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://eva-web-iota.vercel.app',
  "https://eva-backend-production-54ed.up.railway.app/api"
  // Si tienes un dominio personalizado, agrégalo aquí también:
  // 'https://tudominio.com'
];

app.use(cors({
  origin: (origin, callback) => {
    // Permitir peticiones sin origin (Postman, apps móviles, curl)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`CORS bloqueado para origen: ${origin}`);
    return callback(new Error('No permitido por CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Responder preflight OPTIONS en todas las rutas
app.options('*', cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose.set('bufferCommands', false);

// --- CONEXIÓN A MONGODB ---
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000
})
.then(() => console.log("✅ Conexión establecida con MongoDB Atlas"))
.catch(err => {
    console.error("❌ ERROR CRÍTICO DE CONEXIÓN:");
    console.error(err.message);
});

// --- MIDDLEWARE DE AUTENTICACIÓN ---
const verificarToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ message: "No se proporcionó un token de seguridad." });
    }
    const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
    try {
        const verificado = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (error) {
        console.error("JWT Error:", error.message);
        res.status(403).json({ message: "Tu sesión ha expirado o el token es inválido." });
    }
};


// ============================================================
// --- RUTAS DE AUTENTICACIÓN ---
// ============================================================

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, nombre, email, telefono } = req.body;
        if (!username || !password) return res.status(400).json({ message: "Usuario y contraseña son obligatorios" });
        const existe = await User.findOne({ username });
        if (existe) return res.status(400).json({ message: "El usuario ya existe" });
        const salt = await bcrypt.genSalt(10);
        const passwordHashed = await bcrypt.hash(password, salt);
        const nuevoUsuario = new User({ username, password: passwordHashed, nombre: nombre || '', email: email || '', telefono: telefono || '' });
        await nuevoUsuario.save();
        res.status(201).json({ message: "Registro exitoso" });
    } catch (err) {
        res.status(500).json({ message: "Error en registro" });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).json({ message: "La base de datos no está disponible" });
        }
        const usuario = await User.findOne({ username });
        if (!usuario) return res.status(400).json({ message: "Usuario no encontrado" });
        const esValida = await bcrypt.compare(password, usuario.password);
        if (!esValida) return res.status(400).json({ message: "Contraseña incorrecta" });
        const token = jwt.sign(
            { id: usuario._id, username: usuario.username, role: usuario.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        const user = { id: usuario._id, username: usuario.username, role: usuario.role || 'user', nombre: usuario.nombre, email: usuario.email };
        res.json({ message: "Login exitoso", token, user });
    } catch (err) {
        console.error("Error en login:", err);
        res.status(500).json({ message: "Error interno al procesar el login" });
    }
});

app.get('/api/user/profile', verificarToken, async (req, res) => {
    try {
        const usuario = await User.findById(req.user.id).select('-password');
        res.json(usuario);
    } catch (err) {
        res.status(500).json({ message: "Error en perfil" });
    }
});


// ============================================================
// --- RUTAS DE MOVIMIENTOS ---
// ============================================================

app.get('/api/movimientos', verificarToken, async (req, res) => {
    try {
        const movimientos = await Movimiento.find({ userId: req.user.id }).sort({ fecha: -1 });
        res.json(movimientos);
    } catch (error) {
        res.status(500).json({ message: "Error interno al buscar movimientos." });
    }
});

app.get('/api/resumen', verificarToken, async (req, res) => {
    try {
        const movimientos = await Movimiento.find({ userId: req.user.id });
        let ingresos = 0;
        let gastos = 0;
        movimientos.forEach(m => {
            if (m.tipo === 'ingreso') ingresos += m.monto;
            else gastos += m.monto;
        });
        res.json({ saldo: ingresos - gastos, ingresos, gastos });
    } catch (error) {
        res.status(500).json({ message: "Error al calcular el resumen contable." });
    }
});


// ============================================================
// --- RUTAS DE CLIENTES ---
// ============================================================

app.get('/api/clientes', verificarToken, async (req, res) => {
    try {
        const clientes = await Cliente.find({ userId: req.user.id }).sort({ nombre: 1 });
        res.json(clientes);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo clientes" });
    }
});

app.get('/api/clientes/:id', verificarToken, async (req, res) => {
    try {
        const cliente = await Cliente.findOne({ _id: req.params.id, userId: req.user.id });
        if (!cliente) return res.status(404).json({ message: "Cliente no encontrado" });
        res.json(cliente);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo cliente" });
    }
});

app.post('/api/clientes', verificarToken, async (req, res) => {
    try {
        const { nombre, nit, telefono, email, direccion, tipo, ciudad, actividadEconomica } = req.body;
        if (!nombre || !nit) return res.status(400).json({ message: "Nombre y NIT son obligatorios" });
        const existe = await Cliente.findOne({ nit, userId: req.user.id });
        if (existe) return res.status(400).json({ message: "Ya existe un cliente con ese NIT" });
        const cliente = new Cliente({ nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, tipo, userId: req.user.id });
        await cliente.save();
        res.status(201).json({ message: "Cliente creado exitosamente", cliente });
    } catch (err) {
        res.status(500).json({ message: "Error creando cliente" });
    }
});

app.put('/api/clientes/:id', verificarToken, async (req, res) => {
    try {
        const { nombre, nit, telefono, email, direccion, tipo, ciudad, actividadEconomica } = req.body;
        const cliente = await Cliente.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { nombre, nit, ciudad, actividadEconomica, telefono, email, direccion, tipo },
            { new: true, runValidators: true }
        );
        if (!cliente) return res.status(404).json({ message: "Cliente no encontrado" });
        res.json({ message: "Cliente actualizado", cliente });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando cliente" });
    }
});

app.delete('/api/clientes/:id', verificarToken, async (req, res) => {
    try {
        const cliente = await Cliente.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!cliente) return res.status(404).json({ message: "Cliente no encontrado" });
        res.json({ message: "Cliente eliminado" });
    } catch (err) {
        res.status(500).json({ message: "Error eliminando cliente" });
    }
});


// ============================================================
// --- RUTAS DE FACTURAS ---
// ============================================================

app.get('/api/facturas', verificarToken, async (req, res) => {
    try {
        const { estado } = req.query;
        const filtro = { userId: req.user.id };
        if (estado) filtro.estado = estado;
        const facturas = await Factura.find(filtro).sort({ fecha: -1 });
        res.json(facturas);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo facturas" });
    }
});

app.get('/api/facturas/:id', verificarToken, async (req, res) => {
    try {
        const factura = await Factura.findOne({ _id: req.params.id, userId: req.user.id });
        if (!factura) return res.status(404).json({ message: "Factura no encontrada" });
        res.json(factura);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo factura" });
    }
});

app.post('/api/facturas', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, items } = req.body;
        if (!numero || !clienteNombre || subtotal === undefined || total === undefined) {
            return res.status(400).json({ message: "Faltan campos obligatorios" });
        }
        const existe = await Factura.findOne({ numero, userId: req.user.id });
        if (existe) return res.status(400).json({ message: "Ya existe una factura con ese número" });
        const factura = new Factura({ numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, items, userId: req.user.id });
        await factura.save();
        res.status(201).json({ message: "Factura creada exitosamente", factura });
    } catch (err) {
        res.status(500).json({ message: "Error creando factura" });
    }
});

app.put('/api/facturas/:id', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, estado, items } = req.body;
        const factura = await Factura.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { numero, clienteId, clienteNombre, fechaVencimiento, subtotal, iva, total, estado, items },
            { new: true, runValidators: true }
        );
        if (!factura) return res.status(404).json({ message: "Factura no encontrada" });
        res.json({ message: "Factura actualizada", factura });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando factura" });
    }
});

app.patch('/api/facturas/:id/estado', verificarToken, async (req, res) => {
    try {
        const { estado } = req.body;
        if (!['pendiente', 'pagada', 'anulada'].includes(estado)) {
            return res.status(400).json({ message: "Estado no válido" });
        }
        const factura = await Factura.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { estado },
            { new: true }
        );
        if (!factura) return res.status(404).json({ message: "Factura no encontrada" });
        res.json({ message: "Estado actualizado", factura });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando estado" });
    }
});

app.delete('/api/facturas/:id', verificarToken, async (req, res) => {
    try {
        const factura = await Factura.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!factura) return res.status(404).json({ message: "Factura no encontrada" });
        res.json({ message: "Factura eliminada" });
    } catch (err) {
        res.status(500).json({ message: "Error eliminando factura" });
    }
});


// ============================================================
// --- RUTAS DE REMISIONES ---
// ============================================================

app.get('/api/remisiones', verificarToken, async (req, res) => {
    try {
        const { estado } = req.query;
        const filtro = { userId: req.user.id };
        if (estado) filtro.estado = estado;
        const remisiones = await Remision.find(filtro).sort({ fecha: -1 });
        res.json(remisiones);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo remisiones" });
    }
});

app.get('/api/remisiones/:id', verificarToken, async (req, res) => {
    try {
        const remision = await Remision.findOne({ _id: req.params.id, userId: req.user.id });
        if (!remision) return res.status(404).json({ message: "Remisión no encontrada" });
        res.json(remision);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo remisión" });
    }
});

app.post('/api/remisiones', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, direccionEntrega, items } = req.body;
        if (!numero || !clienteNombre) {
            return res.status(400).json({ message: "Número y nombre del cliente son obligatorios" });
        }
        const existe = await Remision.findOne({ numero, userId: req.user.id });
        if (existe) return res.status(400).json({ message: "Ya existe una remisión con ese número" });
        const remision = new Remision({ numero, clienteId, clienteNombre, direccionEntrega, items, userId: req.user.id });
        await remision.save();
        res.status(201).json({ message: "Remisión creada exitosamente", remision });
    } catch (err) {
        res.status(500).json({ message: "Error creando remisión" });
    }
});

app.put('/api/remisiones/:id', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, direccionEntrega, estado, items } = req.body;
        const remision = await Remision.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { numero, clienteId, clienteNombre, direccionEntrega, estado, items },
            { new: true, runValidators: true }
        );
        if (!remision) return res.status(404).json({ message: "Remisión no encontrada" });
        res.json({ message: "Remisión actualizada", remision });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando remisión" });
    }
});

app.patch('/api/remisiones/:id/estado', verificarToken, async (req, res) => {
    try {
        const { estado } = req.body;
        if (!['pendiente', 'entregada', 'anulada'].includes(estado)) {
            return res.status(400).json({ message: "Estado no válido" });
        }
        const remision = await Remision.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { estado },
            { new: true }
        );
        if (!remision) return res.status(404).json({ message: "Remisión no encontrada" });
        res.json({ message: "Estado actualizado", remision });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando estado" });
    }
});

app.delete('/api/remisiones/:id', verificarToken, async (req, res) => {
    try {
        const remision = await Remision.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!remision) return res.status(404).json({ message: "Remisión no encontrada" });
        res.json({ message: "Remisión eliminada" });
    } catch (err) {
        res.status(500).json({ message: "Error eliminando remisión" });
    }
});


// ============================================================
// --- RUTAS DE COTIZACIONES ---
// ============================================================

app.get('/api/cotizaciones', verificarToken, async (req, res) => {
    try {
        const { estado } = req.query;
        const filtro = { userId: req.user.id };
        if (estado) filtro.estado = estado;
        const cotizaciones = await Cotizacion.find(filtro).sort({ fecha: -1 });
        res.json(cotizaciones);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo cotizaciones" });
    }
});

app.get('/api/cotizaciones/:id', verificarToken, async (req, res) => {
    try {
        const cotizacion = await Cotizacion.findOne({ _id: req.params.id, userId: req.user.id });
        if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
        res.json(cotizacion);
    } catch (err) {
        res.status(500).json({ message: "Error obteniendo cotización" });
    }
});

app.post('/api/cotizaciones', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, validez, subtotal, iva, total, items } = req.body;
        if (!numero || !clienteNombre || subtotal === undefined || total === undefined) {
            return res.status(400).json({ message: "Faltan campos obligatorios" });
        }
        const existe = await Cotizacion.findOne({ numero, userId: req.user.id });
        if (existe) return res.status(400).json({ message: "Ya existe una cotización con ese número" });
        const cotizacion = new Cotizacion({ numero, clienteId, clienteNombre, validez, subtotal, iva, total, items, userId: req.user.id });
        await cotizacion.save();
        res.status(201).json({ message: "Cotización creada exitosamente", cotizacion });
    } catch (err) {
        res.status(500).json({ message: "Error creando cotización" });
    }
});

app.put('/api/cotizaciones/:id', verificarToken, async (req, res) => {
    try {
        const { numero, clienteId, clienteNombre, validez, subtotal, iva, total, estado, items } = req.body;
        const cotizacion = await Cotizacion.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { numero, clienteId, clienteNombre, validez, subtotal, iva, total, estado, items },
            { new: true, runValidators: true }
        );
        if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
        res.json({ message: "Cotización actualizada", cotizacion });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando cotización" });
    }
});

app.patch('/api/cotizaciones/:id/estado', verificarToken, async (req, res) => {
    try {
        const { estado } = req.body;
        if (!['pendiente', 'aprobada', 'rechazada', 'convertida'].includes(estado)) {
            return res.status(400).json({ message: "Estado no válido" });
        }
        const cotizacion = await Cotizacion.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { estado },
            { new: true }
        );
        if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
        res.json({ message: "Estado actualizado", cotizacion });
    } catch (err) {
        res.status(500).json({ message: "Error actualizando estado" });
    }
});

app.post('/api/cotizaciones/:id/convertir', verificarToken, async (req, res) => {
    try {
        const cotizacion = await Cotizacion.findOne({ _id: req.params.id, userId: req.user.id });
        if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
        if (cotizacion.estado === 'convertida') return res.status(400).json({ message: "Esta cotización ya fue convertida" });

        const { numeroFactura, fechaVencimiento } = req.body;
        if (!numeroFactura) return res.status(400).json({ message: "Debe indicar el número de factura" });

        const factura = new Factura({
            numero: numeroFactura,
            clienteId: cotizacion.clienteId,
            clienteNombre: cotizacion.clienteNombre,
            fechaVencimiento,
            subtotal: cotizacion.subtotal,
            iva: cotizacion.iva,
            total: cotizacion.total,
            items: cotizacion.items,
            userId: req.user.id
        });
        await factura.save();

        cotizacion.estado = 'convertida';
        await cotizacion.save();

        res.status(201).json({ message: "Cotización convertida en factura", factura });
    } catch (err) {
        res.status(500).json({ message: "Error convirtiendo cotización" });
    }
});

app.delete('/api/cotizaciones/:id', verificarToken, async (req, res) => {
    try {
        const cotizacion = await Cotizacion.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
        if (!cotizacion) return res.status(404).json({ message: "Cotización no encontrada" });
        res.json({ message: "Cotización eliminada" });
    } catch (err) {
        res.status(500).json({ message: "Error eliminando cotización" });
    }
});


// --- INICIAR SERVIDOR ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Servidor EVA activo en puerto ${PORT}`);
});