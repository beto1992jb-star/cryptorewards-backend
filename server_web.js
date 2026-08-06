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
// Ejemplo: 0.001 implica que 1000 puntos = $1.00 USD (40 puntos = $0,04 USD)
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

    // Pedimos una conexión dedicada del pool para la transacción
    const client = await db.connect();

    try {
        await client.query('BEGIN');

        // Bloqueamos la fila del retiro para evitar que dos admins procesen lo mismo al mismo tiempo
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

        // 1. Actualizar el estado de la solicitud
        const updateQuery = 'UPDATE withdrawal_requests SET status = $1 WHERE id = $2 RETURNING *';
        const result = await client.query(updateQuery, [status, id]);

        // 2. Si es RECHAZADO, le devolvemos los puntos correspondientes al usuario
        if (status === 'rejected') {
            // Usamos Math.round para evitar imprecisiones por flotantes de JavaScript
            const pointsToRefund = Math.round(parseFloat(withdrawal.amount) / POINT_TO_CURRENCY_RATIO);

            await client.query(
                'UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2',
                [pointsToRefund, withdrawal.user_id]
            );
        }

        // Si todo salió bien, confirmamos los cambios en la base de datos
        await client.query('COMMIT');

        return res.json({ 
            message: `Solicitud #${id} marcada como ${status}.${status === 'rejected' ? ' Puntos reembolsados al usuario.' : ''}`, 
            withdrawal: result.rows[0] 
        });

    } catch (error) {
        // En caso de cualquier error, se revierten todos los cambios
        await client.query('ROLLBACK');
        console.error('Error al actualizar el estado del retiro:', error);
        return res.status(500).json({ error: 'Error al actualizar el retiro.' });
    } finally {
        // Liberar la conexión para devolverla al pool
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

    // 1. Validar el monto mínimo según el método de pago seleccionado
    if (withdrawAmount < methodConfig.minAmount) {
        return res.status(400).json({ 
            error: `El monto mínimo para solicitar retiro por ${payout_method} es de $${methodConfig.minAmount.toFixed(2)} USD.` 
        });
    }

    // 2. Calcular la comisión con descuento del 50%
    const userFee = (withdrawAmount * methodConfig.fixedFeePercent) + methodConfig.fixedFeeAmount;
    const finalAmountToSend = Math.max(0, withdrawAmount - userFee);

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        // Obtener puntos con bloqueo de fila (FOR UPDATE) para prevenir "race conditions"
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

        // Validar saldo disponible
        if (withdrawAmount > availableBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ 
                error: `Saldo insuficiente. Tienes ${totalPoints} puntos (Equivalente a $${availableBalance.toFixed(2)} USD).` 
            });
        }

        // Registrar la solicitud en estado 'pending' detallando neto y fee
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

        // Calcular puntos exactos a deducir redondeando al entero más cercano
        const pointsToDeduct = Math.round(withdrawAmount / POINT_TO_CURRENCY_RATIO);

        await client.query(
            'UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2',
            [pointsToDeduct, user_id]
        );

        // Confirmar transacción
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
