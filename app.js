const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de Sesión (la "memoria" del login)
app.use(session({
    secret: 'mi-clave-secreta-2026',
    resave: false,
    saveUninitialized: false
}));

const DB_PATH = path.join(__dirname, 'db.json');
const readDB = () => JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

// --- RUTAS DE USUARIOS ---

// Página de Registro
app.get('/registro', (req, res) => res.render('registro'));

app.post('/registro', async (req, res) => {
    const { email, password } = req.body;
    const db = readDB();
    if (!db.users) db.users = [];
    
    const hashedBtn = await bcrypt.hash(password, 10);
    db.users.push({ email, password: hashedBtn });
    writeDB(db);
    res.redirect('/login');
});

// Página de Login
app.get('/login', (req, res) => res.render('login'));

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const db = readDB();
    const user = (db.users || []).find(u => u.email === email);
    
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = email;
        res.redirect('/panel');
    } else {
        res.send('Usuario o contraseña incorrectos');
    }
});

// --- RUTAS PROTEGIDAS ---

// Middleware para ver si está logueado
const checkAuth = (req, res, next) => {
    if (req.session.userId) next();
    else res.redirect('/login');
};

app.get('/panel', checkAuth, (req, res) => {
    const db = readDB();
    // Filtramos las marcas para que cada uno vea solo las suyas (opcional)
    res.send(`Bienvenido ${req.session.userId}. <a href="/editar/nueva">Crear nueva Landing</a>`);
});

// Actualizá tus rutas de editar y guardar con 'checkAuth'
app.get('/editar/:id', checkAuth, (req, res) => {
    const db = readDB();
    const data = db[req.params.id] || {};
    res.render('formulario', { id: req.params.id, data });
});

app.post('/guardar/:id', checkAuth, (req, res) => {
    const dbData = readDB();
    dbData[req.params.id] = { ...req.body, owner: req.session.userId };
    writeDB(dbData);
    res.redirect(`/v/${req.params.id}`);
});

app.get('/v/:id', (req, res) => {
    const db = readDB();
    const data = db[req.params.id];
    if (!data) return res.status(404).send('No encontrada');
    res.render('plantilla', { data });
});

app.listen(3000, () => console.log('SaaS Factory Running'));
