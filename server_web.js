const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();

// Configuración de CORS permitiendo el encabezado x-admin-secret
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'x-admin-secret'],
    credentials: false,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());

// Conexión a Supabase / PostgreSQL
const db = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Clave secreta para panel de administración
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'tu_clave_secreta_admin_123';

// ==========================================
// RUTAS DE ADMINISTRACIÓN
// ==========================================

// 1. Obtener retiros pendientes
app.get('/api/admin/withdrawals/pending', async (req, res) => {
    const secret = req.headers['x-admin-secret'];

    if (secret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado. Clave secreta incorrecta.' });
    }

    try {
        const query = `
            SELECT w.*, u.email 
            FROM withdrawal_requests w
            LEFT JOIN web_users u ON w.user_id = u.id
            WHERE w.status = 'pending'
            ORDER BY w.created_at DESC
        `;
        const result = await db.query(query);
        return res.json({ withdrawals: result.rows });
    } catch (error) {
        console.error('Error al obtener retiros pendientes:', error);
        return res.status(500).json({ error: 'Error al consultar la base de datos.' });
    }
});

// 2. Aprobar o rechazar retiros
app.patch('/api/admin/withdrawals/:id', async (req, res) => {
    const { id } = req.params;
    const { admin_secret, status } = req.body;

    if (admin_secret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado. Clave secreta incorrecta.' });
    }

    if (!['completed', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Estado inválido. Debe ser completed o rejected.' });
    }

    try {
        const updateQuery = 'UPDATE withdrawal_requests SET status = $1 WHERE id = $2 RETURNING *';
        const result = await db.query(updateQuery, [status, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Solicitud de retiro no encontrada.' });
        }

        return res.json({ message: `Solicitud #${id} marcada como ${status}`, withdrawal: result.rows[0] });
    } catch (error) {
        console.error('Error al actualizar el estado del retiro:', error);
        return res.status(500).json({ error: 'Error al actualizar el retiro.' });
    }
});

// ==========================================
// RUTAS DE RETIRO Y USUARIO
// ==========================================

// Endpoint para solicitar retiro de saldo
app.post('/api/withdraw', async (req, res) => {
    const { user_id, amount, payout_method, account_details } = req.body;

    if (!user_id || !amount || !payout_method || !account_details) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ error: 'El monto a retirar debe ser mayor a 0.' });
    }

    try {
        // 1. Obtener puntos de la tabla web_users
        const userResult = await db.query(
            'SELECT points_balance FROM web_users WHERE id = $1',
            [user_id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const totalPoints = parseFloat(userResult.rows[0].points_balance) || 0;

        // 2. Tasa de conversión: Ajusta según tu equivalencia.
        // Ejemplo: 10 puntos = $1.00 USD (0.1 USD por punto)
        const POINT_TO_CURRENCY_RATIO = 0.1; 
        const availableBalance = totalPoints * POINT_TO_CURRENCY_RATIO;

        // 3. Validar saldo disponible
        if (withdrawAmount > availableBalance) {
            return res.status(400).json({ 
                error: `Saldo insuficiente. Tienes ${totalPoints} puntos (Equivalente a $${availableBalance.toFixed(2)} USD).` 
            });
        }

        // 4. Registrar la solicitud en estado 'pending'
        const insertQuery = `
            INSERT INTO withdrawal_requests (user_id, amount, payout_method, account_details)
            VALUES ($1, $2, $3, $4)
            RETURNING *;
        `;
        const newWithdrawal = await db.query(insertQuery, [user_id, withdrawAmount, payout_method, account_details]);

        // 5. Restar los puntos equivalentes al usuario
        const pointsToDeduct = withdrawAmount / POINT_TO_CURRENCY_RATIO;
        await db.query(
            'UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2',
            [pointsToDeduct, user_id]
        );

        return res.status(201).json({
            message: 'Solicitud de retiro registrada con éxito.',
            withdrawal: newWithdrawal.rows[0],
            new_balance: (availableBalance - withdrawAmount).toFixed(2)
        });

    } catch (error) {
        console.error('Error al procesar el retiro:', error);
        return res.status(500).json({ error: 'Error interno del servidor al procesar la solicitud.' });
    }
});

// Endpoint para obtener el saldo y el historial de retiros de un usuario
app.get('/api/withdrawals/:user_id', async (req, res) => {
    const { user_id } = req.params;

    try {
        const history = await db.query(
            'SELECT * FROM withdrawal_requests WHERE user_id = $1 ORDER BY created_at DESC',
            [user_id]
        );

        return res.json({ withdrawals: history.rows });
    } catch (error) {
        console.error('Error al obtener retiros:', error);
        return res.status(500).json({ error: 'Error al obtener el historial de retiros.' });
    }
});

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// Ruta raíz de comprobación
app.get('/', (req, res) => {
    res.status(200).send('Servidor GanaRecompensasEnLaWeb funcionando correctamente 🚀');
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

// 2. INICIO DE SESIÓN
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
            newBalance: parseFloat(user.points_balance) + points
        });
    } catch (err) {
        console.error('Error en video reward:', err);
        return res.status(500).json({ error: 'Error interno en el servidor' });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));
