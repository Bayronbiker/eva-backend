require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Importar modelos
const User = require('./models/User');
const Movimiento = require('./models/Movimiento');
const Factura = require('./models/Factura');
const Cliente = require('./models/Cliente');
const Cotizacion = require('./models/Cotizacion');
const Remision = require('./models/Remision');

const app = express();

// Middlewares
// Configuración más específica de CORS
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'], // URL de tu frontend React
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ Conectado a MongoDB"))
    .catch(err => console.error("❌ Error de conexión:", err));

// Middleware de autenticación
const verificarToken = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Acceso denegado. No hay token." });

    try {
        const verificado = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (error) {
        res.status(400).json({ message: "Token inválido" });
    }
};

// --- RUTAS DE AUTENTICACIÓN ---

// Registro
app.post('/api/register', async (req, res) => {
    try {
        const { username, password, role = 'user' } = req.body;
        
        // Verificar si el usuario ya existe
        const existeUsuario = await User.findOne({ username });
        if (existeUsuario) return res.status(400).json({ message: "El usuario ya existe" });

        // Encriptar contraseña
        const salt = await bcrypt.genSalt(10);
        const passwordHashed = await bcrypt.hash(password, salt);

        const nuevoUsuario = new User({
            username,
            password: passwordHashed,
            role
        });

        await nuevoUsuario.save();
        
        // Crear token
        const token = jwt.sign(
            { id: nuevoUsuario._id, username: nuevoUsuario.username, role: nuevoUsuario.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            message: "Registro exitoso",
            token,
            user: {
                id: nuevoUsuario._id,
                username: nuevoUsuario.username,
                role: nuevoUsuario.role
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error en el servidor" });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const usuario = await User.findOne({ username });
        if (!usuario) return res.status(400).json({ message: "Usuario no encontrado" });

        const esValida = await bcrypt.compare(password, usuario.password);
        if (!esValida) return res.status(400).json({ message: "Contraseña incorrecta" });

        const token = jwt.sign(
            { id: usuario._id, username: usuario.username, role: usuario.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: "Login exitoso",
            token,
            user: {
                id: usuario._id,
                username: usuario.username,
                role: usuario.role
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error en el servidor" });
    }
});

// --- RUTAS PROTEGIDAS ---

// Perfil de usuario
app.get('/api/user/profile', verificarToken, async (req, res) => {
    try {
        const usuario = await User.findById(req.user.id).select('-password');
        if (!usuario) return res.status(404).json({ message: "Usuario no encontrado" });
        
        res.json({
            id: usuario._id,
            username: usuario.username,
            role: usuario.role,
            nombre: usuario.nombre,
            email: usuario.email,
            telefono: usuario.telefono,
            createdAt: usuario.createdAt
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error al obtener perfil" });
    }
});

// --- BÚSQUEDA GLOBAL ---
app.get('/api/search/global', verificarToken, async (req, res) => {
    try {
        const { q } = req.query;
        if (!q || q.length < 2) return res.json([]);

        const userId = req.user.id;
        const resultados = [];

        // Buscar en facturas
        const facturas = await Factura.find({
            userId,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(5);

        facturas.forEach(f => resultados.push({
            tipo: 'factura',
            id: f._id,
            numero: f.numero,
            cliente: f.clienteNombre,
            monto: f.total,
            fecha: f.fecha
        }));

        // Buscar en clientes
        const clientes = await Cliente.find({
            userId,
            $or: [
                { nombre: { $regex: q, $options: 'i' } },
                { nit: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } }
            ]
        }).limit(5);

        clientes.forEach(c => resultados.push({
            tipo: 'cliente',
            id: c._id,
            nombre: c.nombre,
            nit: c.nit,
            telefono: c.telefono,
            email: c.email
        }));

        // Buscar en cotizaciones
        const cotizaciones = await Cotizacion.find({
            userId,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(5);

        cotizaciones.forEach(c => resultados.push({
            tipo: 'cotizacion',
            id: c._id,
            numero: c.numero,
            cliente: c.clienteNombre,
            monto: c.total,
            fecha: c.fecha
        }));

        // Buscar en remisiones
        const remisiones = await Remision.find({
            userId,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(5);

        remisiones.forEach(r => resultados.push({
            tipo: 'remision',
            id: r._id,
            numero: r.numero,
            cliente: r.clienteNombre,
            fecha: r.fecha
        }));

        res.json(resultados);
    } catch (error) {
        console.error("Error en búsqueda global:", error);
        res.status(500).json({ message: "Error en búsqueda" });
    }
});

// --- BÚSQUEDAS ESPECÍFICAS ---

app.get('/api/facturas/search', verificarToken, async (req, res) => {
    try {
        const { q } = req.query;
        const facturas = await Factura.find({
            userId: req.user.id,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(10);
        res.json(facturas);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error buscando facturas" });
    }
});

app.get('/api/clientes/search', verificarToken, async (req, res) => {
    try {
        const { q } = req.query;
        const clientes = await Cliente.find({
            userId: req.user.id,
            $or: [
                { nombre: { $regex: q, $options: 'i' } },
                { nit: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } }
            ]
        }).limit(10);
        res.json(clientes);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error buscando clientes" });
    }
});

app.get('/api/cotizaciones/search', verificarToken, async (req, res) => {
    try {
        const { q } = req.query;
        const cotizaciones = await Cotizacion.find({
            userId: req.user.id,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(10);
        res.json(cotizaciones);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error buscando cotizaciones" });
    }
});

app.get('/api/remisiones/search', verificarToken, async (req, res) => {
    try {
        const { q } = req.query;
        const remisiones = await Remision.find({
            userId: req.user.id,
            $or: [
                { numero: { $regex: q, $options: 'i' } },
                { clienteNombre: { $regex: q, $options: 'i' } }
            ]
        }).limit(10);
        res.json(remisiones);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error buscando remisiones" });
    }
});

// --- CRUD PARA MOVIMIENTOS ---

// Obtener movimientos
app.get('/api/movimientos', verificarToken, async (req, res) => {
    try {
        const movimientos = await Movimiento.find({ userId: req.user.id }).sort({ fecha: -1 });
        res.json(movimientos);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error al obtener movimientos" });
    }
});

// Crear movimiento
app.post('/api/movimientos', verificarToken, async (req, res) => {
    try {
        const movimiento = new Movimiento({
            ...req.body,
            userId: req.user.id
        });
        await movimiento.save();
        res.status(201).json(movimiento);
    } catch (error) {
        console.error(error);
        res.status(400).json({ message: "Error creando movimiento" });
    }
});

// Obtener resumen
app.get('/api/resumen', verificarToken, async (req, res) => {
    try {
        const movimientos = await Movimiento.find({ userId: req.user.id });
        
        let ingresos = 0;
        let gastos = 0;

        movimientos.forEach(m => {
            if (m.tipo === 'ingreso') ingresos += m.monto;
            else gastos += m.monto;
        });

        res.json({
            saldo: ingresos - gastos,
            ingresos: ingresos,
            gastos: gastos
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error al calcular resumen" });
    }
});

// --- CRUD PARA FACTURAS ---

// Obtener todas las facturas
app.get('/api/facturas', verificarToken, async (req, res) => {
    try {
        const facturas = await Factura.find({ userId: req.user.id })
            .populate('clienteId', 'nombre nit')
            .sort({ fecha: -1 });
        res.json(facturas);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo facturas" });
    }
});

// Crear factura
app.post('/api/facturas', verificarToken, async (req, res) => {
    try {
        // Generar número de factura
        const count = await Factura.countDocuments({ userId: req.user.id });
        const numero = `FAC-${(count + 1).toString().padStart(4, '0')}`;
        
        const factura = new Factura({
            ...req.body,
            numero,
            userId: req.user.id
        });
        await factura.save();
        res.status(201).json(factura);
    } catch (error) {
        console.error(error);
        res.status(400).json({ message: "Error creando factura" });
    }
});

// Obtener una factura por ID
app.get('/api/facturas/:id', verificarToken, async (req, res) => {
    try {
        const factura = await Factura.findOne({
            _id: req.params.id,
            userId: req.user.id
        }).populate('clienteId');
        
        if (!factura) return res.status(404).json({ message: "Factura no encontrada" });
        
        res.json(factura);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo factura" });
    }
});

// --- CRUD PARA CLIENTES ---

// Obtener todos los clientes
app.get('/api/clientes', verificarToken, async (req, res) => {
    try {
        const clientes = await Cliente.find({ userId: req.user.id }).sort({ nombre: 1 });
        res.json(clientes);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo clientes" });
    }
});

// Crear cliente
app.post('/api/clientes', verificarToken, async (req, res) => {
    try {
        // Verificar si ya existe un cliente con el mismo NIT
        const clienteExistente = await Cliente.findOne({
            nit: req.body.nit,
            userId: req.user.id
        });
        
        if (clienteExistente) {
            return res.status(400).json({ message: "Ya existe un cliente con este NIT" });
        }

        const cliente = new Cliente({
            ...req.body,
            userId: req.user.id
        });
        await cliente.save();
        res.status(201).json(cliente);
    } catch (error) {
        console.error(error);
        res.status(400).json({ message: "Error creando cliente" });
    }
});

// Obtener un cliente por ID
app.get('/api/clientes/:id', verificarToken, async (req, res) => {
    try {
        const cliente = await Cliente.findOne({
            _id: req.params.id,
            userId: req.user.id
        });
        
        if (!cliente) return res.status(404).json({ message: "Cliente no encontrado" });
        
        res.json(cliente);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo cliente" });
    }
});

// --- CRUD BÁSICO PARA COTIZACIONES ---

app.get('/api/cotizaciones', verificarToken, async (req, res) => {
    try {
        const cotizaciones = await Cotizacion.find({ userId: req.user.id }).sort({ fecha: -1 });
        res.json(cotizaciones);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo cotizaciones" });
    }
});

app.post('/api/cotizaciones', verificarToken, async (req, res) => {
    try {
        const count = await Cotizacion.countDocuments({ userId: req.user.id });
        const numero = `COT-${(count + 1).toString().padStart(4, '0')}`;
        
        const cotizacion = new Cotizacion({
            ...req.body,
            numero,
            userId: req.user.id
        });
        await cotizacion.save();
        res.status(201).json(cotizacion);
    } catch (error) {
        console.error(error);
        res.status(400).json({ message: "Error creando cotización" });
    }
});

// --- CRUD BÁSICO PARA REMISIONES ---

app.get('/api/remisiones', verificarToken, async (req, res) => {
    try {
        const remisiones = await Remision.find({ userId: req.user.id }).sort({ fecha: -1 });
        res.json(remisiones);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo remisiones" });
    }
});

app.post('/api/remisiones', verificarToken, async (req, res) => {
    try {
        const count = await Remision.countDocuments({ userId: req.user.id });
        const numero = `REM-${(count + 1).toString().padStart(4, '0')}`;
        
        const remision = new Remision({
            ...req.body,
            numero,
            userId: req.user.id
        });
        await remision.save();
        res.status(201).json(remision);
    } catch (error) {
        console.error(error);
        res.status(400).json({ message: "Error creando remisión" });
    }
});

// --- ENDPOINTS PARA LA APP MÓVIL (Kotlin) ---

// Endpoint para obtener facturas con filtros (usado en la app Kotlin)
app.get('/api/facturas-app', verificarToken, async (req, res) => {
    try {
        const { estado, fechaInicio, fechaFin, search } = req.query;
        let query = { userId: req.user.id };

        if (estado && estado !== 'todos') query.estado = estado;
        if (fechaInicio && fechaFin) {
            query.fecha = {
                $gte: new Date(fechaInicio),
                $lte: new Date(fechaFin)
            };
        }
        if (search) {
            query.$or = [
                { numero: { $regex: search, $options: 'i' } },
                { clienteNombre: { $regex: search, $options: 'i' } }
            ];
        }

        const facturas = await Factura.find(query).sort({ fecha: -1 });
        res.json(facturas);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error obteniendo facturas" });
    }
});

// --- RUTA DE PRUEBA ---
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Backend EVA funcionando',
        timestamp: new Date().toISOString()
    });
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor EVA corriendo en: http://localhost:${PORT}`);
    console.log(`🔗 URL: http://localhost:${PORT}`);
});