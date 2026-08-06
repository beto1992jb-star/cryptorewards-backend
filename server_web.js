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

// Tasa de conversión global: Define cuántos USD vale cada punto
// Ejemplo: 0.001 implica que 1000 puntos = $1.00 USD (1 punto = $0.001 USD)
const POINT_TO_CURRENCY_RATIO = 0.001; 

// Configuración de límites y comisiones fijadas por método (Mínimos y 50% de comisión)
const PAYOUT_CONFIG = {
    binance: {
        minAmount: 1.00,
        fixedFeePercent: 0.0, // Binance Pay sin comisión
        fixedFeeAmount: 0.0
    },
    mercadopago: {
        minAmount: 1.00,
        fixedFeePercent: 0.0,
        fixedFeeAmount: 0.15 // 50% de $0.30 USD aprox
    },
    paypal: {
        minAmount: 5.00,
        fixedFeePercent: 0.015, // 50% de 3% (1.5%)
        fixedFeeAmount: 0.20   // 50% de $0.40 USD
    }
};

// ==========================================
// ENDPOINT DE POSTBACK DE CPX RESEARCH
// ==========================================
app.get('/api/cpx-postback', async (req, res) => {
    const { user_id, amount_local, amount_usd, trans_id, status } = req.query;

    console.log('Postback CPX recibido:', { user_id, amount_local, amount_usd, trans_id, status });

    if (!user_id || !trans_id || !status) {
        return res.status(400).send('Parámetros requeridos faltantes.');
    }

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        // Verificar si el usuario existe
        const userCheck = await client.query('SELECT id FROM web_users WHERE id = $1', [user_id]);
        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).send('Usuario no encontrado.');
        }

        // Calcular los puntos a acreditar a partir de amount_local o amount_usd
        // Si usaste 1 USD = 1000 puntos, los puntos coinciden con amount_local (o amount_usd / 0.001)
        const pointsAwarded = Math.round(parseFloat(amount_local) || (parseFloat(amount_usd) / POINT_TO_CURRENCY_RATIO));

        if (status === '1') {
            // Acreditar o procesar nuevo bono/encuesta
            // 1. Aumentar balance del usuario
            await client.query(
                'UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2',
                [pointsAwarded, user_id]
            );

            // 2. Registrar evento de recompensa
            await client.query(
                'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
                [user_id, 'CPX_RESEARCH', trans_id, pointsAwarded]
            );

        } else if (status === '2') {
            // Reversión por fraude o cancelación
            // 1. Restar los puntos acreditados anteriormente
            await client.query(
                'UPDATE web_users SET points_balance = GREATEST(0, points_balance - $1) WHERE id = $2',
                [pointsAwarded, user_id]
            );

            // 2. Registrar la cancelación
            await client.query(
                'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
                [user_id, 'CPX_RESEARCH_REVERSED', trans_id, -pointsAwarded]
            );
        }

        await client.query('COMMIT');

        // CPX exige respuesta HTTP 200 con "OK" u "1"
        return res.status(200).send('OK');

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al procesar el Postback de CPX:', error);
        return res.status(500).send('Error interno en el servidor.');
    } finally {
        client.release();
    }
});

// ==========================================
// RUTAS DE ADMINISTRACIÓN (OPTIMIZADAS)
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

// 2. Aprobar o rechazar retiros (Con Transacción Atómica y Reembolso Seguro)
app.patch('/api/admin/withdrawals/:id', async (req, res) => {
    const { id } = req.params;
    const { admin_secret, status } = req.body;

    if (admin_secret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado. Clave secreta incorrecta.' });
    }

    if (!['completed', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Estado inválido. Debe ser completed o rejected.' });
    }

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const checkQuery = 'SELECT * FROM withdrawal_requests WHERE id = $1 FOR UPDATE';
        const checkResult = await client.query(checkQuery, [id]);

        if (checkResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Solicitud de retiro no encontrada.' });
        }

        const withdrawal = checkResult.rows[0];

        if (withdrawal.status !== 'pending') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: `La solicitud ya fue procesada previamente como: ${withdrawal.status}` });
        }

        const updateQuery = 'UPDATE withdrawal_requests SET status = $1 WHERE id = $2 RETURNING *';
        const result = await client.query(updateQuery, [status, id]);

        if (status === 'rejected') {
            const pointsToRefund = Math.round(parseFloat(withdrawal.amount) / POINT_TO_CURRENCY_RATIO);

            await client.query(
                'UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2',
                [pointsToRefund, withdrawal.user_id]
            );
        }

        await client.query('COMMIT');

        return res.json({ 
            message: `Solicitud #${id} marcada como ${status}.${status === 'rejected' ? ' Puntos reembolsados al usuario.' : ''}`, 
            withdrawal: result.rows[0] 
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al actualizar el estado del retiro:', error);
        return res.status(500).json({ error: 'Error al actualizar el retiro.' });
    } finally {
        client.release();
    }
});

// ==========================================
// RUTAS DE RETIRO Y USUARIO (OPTIMIZADAS)
// ==========================================

// Endpoint para solicitar retiro de saldo con validación de mínimos y comisiones
app.post('/api/withdraw', async (req, res) => {
    const { user_id, amount, payout_method, account_details } = req.body;

    if (!user_id || !amount || !payout_method || !account_details) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    const methodKey = payout_method.toLowerCase().trim();
    const methodConfig = PAYOUT_CONFIG[methodKey];

    if (!methodConfig) {
        return res.status(400).json({ error: 'Método de pago no válido. Opciones permitidas: binance, mercadopago, paypal.' });
    }

    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
        return res.status(400).json({ error: 'El monto a retirar debe ser mayor a 0.' });
    }

    if (withdrawAmount < methodConfig.minAmount) {
        return res.status(400).json({ 
            error: `El monto mínimo para solicitar retiro por ${payout_method} es de $${methodConfig.minAmount.toFixed(2)} USD.` 
        });
    }

    const userFee = (withdrawAmount * methodConfig.fixedFeePercent) + methodConfig.fixedFeeAmount;
    const finalAmountToSend = Math.max(0, withdrawAmount - userFee);

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const userResult = await client.query(
            'SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE',
            [user_id]
        );

        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const totalPoints = parseFloat(userResult.rows[0].points_balance) || 0;
        const availableBalance = totalPoints * POINT_TO_CURRENCY_RATIO;

        if (withdrawAmount > availableBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                error: `Saldo insuficiente. Tienes ${totalPoints} puntos (Equivalente a $${availableBalance.toFixed(2)} USD).` 
            });
        }

        const insertQuery = `
            INSERT INTO withdrawal_requests (user_id, amount, payout_method, account_details)
            VALUES ($1, $2, $3, $4)
            RETURNING *;
        `;
        const newWithdrawal = await client.query(insertQuery, [
            user_id, 
            withdrawAmount, 
            `${payout_method} (Neto: $${finalAmountToSend.toFixed(2)} USD - Fee: $${userFee.toFixed(2)})`, 
            account_details
        ]);

        const pointsToDeduct = Math.round(withdrawAmount / POINT_TO_CURRENCY_RATIO);

        await client.query(
            'UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2',
            [pointsToDeduct, user_id]
        );

        await client.query('COMMIT');

        return res.status(201).json({
            message: 'Solicitud de retiro registrada con éxito.',
            withdrawal: newWithdrawal.rows[0],
            fee_applied: userFee.toFixed(2),
            net_amount: finalAmountToSend.toFixed(2),
            new_balance: ((totalPoints - pointsToDeduct) * POINT_TO_CURRENCY_RATIO).toFixed(2)
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al procesar el retiro:', error);
        return res.status(500).json({ error: 'Error interno del servidor al procesar la solicitud.' });
    } finally {
        client.release();
    }
});

// Endpoint para obtener el historial de retiros de un usuario
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

        await client.query(
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
