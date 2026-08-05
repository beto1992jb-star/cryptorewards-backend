const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();

// Configuración explícita de CORS
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
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
            newBalance: user.points_balance + points
        });
    } catch (err) {
        console.error('Error en video reward:', err);
        return res.status(500).json({ error: 'Error interno en el servidor' });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`));

// Clave secreta para proteger los endpoints administrativos
// Recomendado ponerla en las Variables de Entorno de Render como ADMIN_SECRET
const ADMIN_SECRET = process.env.ADMIN_SECRET || "tu_clave_secreta_admin_123";

// PATCH /api/admin/withdrawals/:id
app.patch('/api/admin/withdrawals/:id', async (req, res) => {
    const { id } = req.params; // ID de la solicitud de retiro
    const { status, admin_secret } = req.body; // status: 'completed' o 'rejected'

    // 1. Validar Clave Administrador
    if (admin_secret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado. Clave administrativa incorrecta.' });
    }

    // 2. Validar Estado
    if (!['completed', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Estado no válido. Use "completed" o "rejected".' });
    }

    try {
        // 3. Obtener la solicitud actual
        const { data: withdrawal, error: fetchError } = await supabase
            .from('withdrawals')
            .select('*')
            .eq('id', id)
            .single();

        if (fetchError || !withdrawal) {
            return res.status(404).json({ error: 'Solicitud de retiro no encontrada.' });
        }

        // Evitar procesar solicitudes que ya no están pendientes
        if (withdrawal.status !== 'pending') {
            return res.status(400).json({ error: `La solicitud ya fue procesada anteriormente como "${withdrawal.status}".` });
        }

        // 4. Si el estado es REJECTED, reembolsar los puntos al usuario
        if (status === 'rejected') {
            // Calcular puntos a reembolsar (1 USD = 1000 puntos)
            const pointsToRefund = Math.round(withdrawal.amount * 1000);

            // Obtener saldo actual del usuario
            const { data: user, error: userError } = await supabase
                .from('users')
                .select('points_balance')
                .eq('id', withdrawal.user_id)
                .single();

            if (!userError && user) {
                const newBalance = (user.points_balance || 0) + pointsToRefund;
                
                // Actualizar saldo del usuario
                await supabase
                    .from('users')
                    .update({ points_balance: newBalance })
                    .eq('id', withdrawal.user_id);
            }
        }

        // 5. Actualizar el estado de la solicitud en la base de datos
        const { data: updatedWithdrawal, error: updateError } = await supabase
            .from('withdrawals')
            .update({ 
                status: status,
                updated_at: new Date()
            })
            .eq('id', id)
            .select()
            .single();

        if (updateError) {
            throw updateError;
        }

        return res.status(200).json({
            success: true,
            message: `Solicitud ${id} actualizada a "${status}" con éxito.`,
            withdrawal: updatedWithdrawal
        });

    } catch (error) {
        console.error('Error al actualizar retiro:', error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// GET /api/admin/withdrawals/pending
app.get('/api/admin/withdrawals/pending', async (req, res) => {
    const adminSecret = req.headers['x-admin-secret'];

    if (adminSecret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado.' });
    }

    try {
        const { data, error } = await supabase
            .from('withdrawals')
            .select('*, users(email)')
            .eq('status', 'pending')
            .order('created_at', { ascending: false });

        if (error) throw error;

        res.status(200).json({ success: true, withdrawals: data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
