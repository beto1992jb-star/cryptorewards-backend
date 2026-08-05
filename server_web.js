const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();

// Configuración explicita de CORS
const corsOptions = {
    origin: '*', // O tu URL exacta de Netlify: 'https://cryptorewards-app.netlify.app'
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    credentials: false,
    optionsSuccessStatus: 200 // Para compatibilidad con navegadores antiguos (IE11/Smart TVs)
};

// 1. Aplicar middleware general de CORS
app.use(cors(corsOptions));

// 2. Habilitar explícitamente las respuestas Preflight (OPTIONS) para TODAS las rutas
app.options('*', cors(corsOptions));

app.use(express.json());

// Conexión a Supabase / PostgreSQL
const db = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Ruta raíz
app.get('/', (req, res) => {
    res.status(200).send('Servidor CryptoRewards Web funcionando correctamente 🚀');
});

// 1. REGISTRO DE USUARIO
app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    try {
        const checkUser = await db.query('SELECT id FROM web_users WHERE email = $1', [email]);
        if (checkUser.rows.length > 0) {
            return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
        }

        const hashedPassword = hashPassword(password);
        const newUser = await db.query(
            `INSERT INTO web_users (email, password_hash, points_balance, tier_level) 
             VALUES ($1, $2, 0, 1) RETURNING id, email, points_balance`,
            [email, hashedPassword]
        );

        return res.json({ success: true, user: newUser.rows[0] });
    } catch (err) {
        console.error('Error en registro:', err);
        return res.status(500).json({ error: 'Error al registrar el usuario' });
    }
});

// 2. INICIO DE SESIÓN (LOGIN)
app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const hashedPassword = hashPassword(password);
        const userRes = await db.query(
            'SELECT id, email, points_balance FROM web_users WHERE email = $1 AND password_hash = $2',
            [email, hashedPassword]
        );

        if (userRes.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        return res.json({ success: true, user: userRes.rows[0] });
    } catch (err) {
        console.error('Error en login:', err);
        return res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

// 3. OBTENER SALDO
app.get('/api/v1/user/balance/:userId', async (req, res) => {
    try {
        const userRes = await db.query('SELECT points_balance FROM web_users WHERE id = $1', [req.params.userId]);
        if (userRes.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        return res.json({ success: true, balance: userRes.rows[0].points_balance });
    } catch (err) {
        return res.status(500).json({ error: 'Error al obtener el saldo' });
    }
});

// 4. RECOMPENSA DE VIDEO
app.post('/api/v1/web-video-reward', async (req, res) => {
    const { userId } = req.body;

    try {
        const userRes = await db.query(
            'SELECT tier_level, daily_videos_watched, last_video_date, points_balance FROM web_users WHERE id = $1', 
            [userId]
        );
        if (userRes.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const user = userRes.rows[0];
        const today = new Date().toISOString().split('T')[0];
        let watchedCount = user.daily_videos_watched || 0;
        const lastDate = user.last_video_date ? user.last_video_date.toISOString().split('T')[0] : '';

        if (lastDate !== today) {
            watchedCount = 0;
        }

        if (watchedCount >= 30) {
            return res.status(400).json({ error: 'Límite diario alcanzado (30/30)' });
        }

        const points = user.tier_level === 1 ? 10 : 3;
        const transId = `WEB_VID_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        await db.query(
            `UPDATE web_users 
             SET points_balance = points_balance + $1, 
                 daily_videos_watched = $2 + 1, 
                 last_video_date = $3 
             WHERE id = $4`,
            [points, watchedCount, today, userId]
        );

        await db.query(
            'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4)',
            [userId, 'WEB_VIDEO', transId, points]
        );

        return res.json({ 
            success: true, 
            pointsAwarded: points, 
            newTotalWatched: watchedCount + 1,
            newBalance: user.points_balance + points
        });
    } catch (err) {
        console.error('Error en video reward:', err);
        return res.status(500).json({ error: 'Error interno en el servidor' });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
