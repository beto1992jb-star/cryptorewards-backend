const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// ==========================================
// CONFIGURACIÓN Y VARIABLES DE ENTORNO
// ==========================================
const JWT_SECRET = process.env.JWT_SECRET || 'super_secreto_jwt_cambiar_en_produccion';
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const CPX_HASH_SECRET = process.env.CPX_HASH_SECRET;

const POINT_TO_CURRENCY_RATIO = 0.001; // 1000 puntos = $1.00 USD

const PAYOUT_CONFIG = {
    binance: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.0 },
    mercadopago: { minAmount: 5.00, fixedFeePercent: 0.0, fixedFeeAmount: 0.15 },
    paypal: { minAmount: 5.00, fixedFeePercent: 0.015, fixedFeeAmount: 0.20 }
};

const corsOptions = {
    origin: process.env.ALLOWED_ORIGIN || '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'x-admin-secret'],
    credentials: false,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// Conexión a PostgreSQL / Supabase con SSL ajustado
const db = new Pool({ 
    connectionString: process.env.DATABASE_URL,
    ssl: { 
        rejectUnauthorized: false 
    }
});

// Captura de errores globales del pool de BD para evitar que el proceso colapse
db.on('error', (err) => {
    console.error('Error inesperado en cliente inactivo de PostgreSQL:', err);
});

// ==========================================
// MIDDLEWARES DE SEGURIDAD
// ==========================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Acceso denegado. Token no provisto.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Token inválido o expirado.' });
    }
};

const verifyAdmin = (req, res, next) => {
    const secret = req.headers['x-admin-secret'] || req.body.admin_secret;
    if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
        return res.status(401).json({ error: 'No autorizado. Clave de administración incorrecta.' });
    }
    next();
};

// ==========================================
// ENDPOINT DE POSTBACK DE CPX RESEARCH
// ==========================================
app.get('/api/cpx-postback', async (req, res) => {
    const { user_id, amount_local, amount_usd, trans_id, status, hash } = req.query;

    if (!user_id || !trans_id || !status) {
        return res.status(400).send('Parámetros requeridos faltantes.');
    }

    if (CPX_HASH_SECRET && hash) {
        const computedHash = crypto.createHash('md5')
            .update(`${trans_id}-${CPX_HASH_SECRET}`)
            .digest('hex');
            
        if (computedHash.toLowerCase() !== hash.toLowerCase()) {
            return res.status(403).send('Firma de postback inválida.');
        }
    }

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const userCheck = await client.query('SELECT id FROM web_users WHERE id = $1', [user_id]);
        if (userCheck.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).send('Usuario no encontrado.');
        }

        const rawAmount = parseFloat(amount_local) || (parseFloat(amount_usd) / POINT_TO_CURRENCY_RATIO) || 0;
        const pointsAwarded = Math.round(rawAmount);

        if (status === '1') {
            const existingTx = await client.query(
                'SELECT id FROM web_reward_events WHERE trans_id = $1',
                [trans_id]
            );

            if (existingTx.rows.length === 0) {
                await client.query(
                    'UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2',
                    [pointsAwarded, user_id]
                );

                await client.query(
                    'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4) ON CONFLICT (trans_id) DO NOTHING',
                    [user_id, 'CPX_RESEARCH', trans_id, pointsAwarded]
                );
            }
        } else if (status === '2') {
            const originalTx = await client.query(
                'SELECT points_awarded FROM web_reward_events WHERE trans_id = $1',
                [trans_id]
            );

            if (originalTx.rows.length > 0) {
                const originalPoints = originalTx.rows[0].points_awarded;

                await client.query(
                    'UPDATE web_users SET points_balance = GREATEST(0, points_balance - $1) WHERE id = $2',
                    [originalPoints, user_id]
                );

                await client.query(
                    'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4) ON CONFLICT (trans_id) DO NOTHING',
                    [user_id, 'CPX_RESEARCH_REVERSED', `${trans_id}_REV`, -originalPoints]
                );
            }
        }

        await client.query('COMMIT');
        return res.status(200).send('OK');

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al procesar Postback CPX:', error);
        return res.status(500).send('Error interno en el servidor.');
    } finally {
        client.release();
    }
});

// ==========================================
// RUTAS AUTENTICADAS DE USUARIO
// ==========================================

// Registro de Usuario
app.post('/api/v1/auth/register', async (req, res) => {
    const { email, password, referral_code, country_code } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña requeridos.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const userCountry = (country_code || 'AR').toUpperCase();
    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const checkUser = await client.query('SELECT id FROM web_users WHERE email = $1', [normalizedEmail]);
        if (checkUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'El correo electrónico ya está registrado.' });
        }

        let referrerId = null;
        if (referral_code && referral_code.trim() !== '') {
            const referrerCheck = await client.query(
                'SELECT id FROM web_users WHERE referral_code = $1', 
                [referral_code.trim().toUpperCase()]
            );
            if (referrerCheck.rows.length > 0) {
                referrerId = referrerCheck.rows[0].id;
            }
        }

        const myReferralCode = crypto.randomBytes(4).toString('hex').toUpperCase();
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await client.query(
            `INSERT INTO web_users (email, password_hash, country_code, referral_code, referred_by) 
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id, email, country_code, tier_level, points_balance, referral_code, total_referrals`,
            [normalizedEmail, hashedPassword, userCountry, myReferralCode, referrerId]
        );

        if (referrerId) {
            const REFERRAL_BONUS = 100;
            await client.query(
                `UPDATE web_users 
                 SET points_balance = points_balance + $1, 
                     total_referrals = total_referrals + 1 
                 WHERE id = $2`,
                [REFERRAL_BONUS, referrerId]
            );

            await client.query(
                'INSERT INTO web_reward_events (user_id, source_type, trans_id, points_awarded) VALUES ($1, $2, $3, $4)',
                [referrerId, 'REFERRAL_BONUS', `REF_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`, REFERRAL_BONUS]
            );
        }

        await client.query('COMMIT');

        const userPayload = newUser.rows[0];
        const token = jwt.sign({ userId: userPayload.id, email: userPayload.email }, JWT_SECRET, { expiresIn: '7d' });

        return res.json({ success: true, user: userPayload, token });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error en registro:', err);
        return res.status(500).json({ error: 'Error al registrar el usuario.' });
    } finally {
        client.release();
    }
});

// Login
app.post('/api/v1/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña requeridos.' });
    }

    try {
        const userRes = await db.query(
            `SELECT id, email, password_hash, binance_id, country_code, tier_level, 
                    points_balance, daily_videos_watched, referral_code, total_referrals 
             FROM web_users WHERE email = $1`,
            [email.toLowerCase().trim()]
        );

        if (userRes.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        const user = userRes.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales incorrectas.' });
        }

        delete user.password_hash;
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        return res.json({ success: true, user, token });
    } catch (err) {
        console.error('Error en login:', err);
        return res.status(500).json({ error: 'Error al iniciar sesión.' });
    }
});

// Solicitud de Retiro
app.post('/api/withdraw', verifyToken, async (req, res) => {
    const userId = req.user.userId;
    const { amount, payout_method, account_details } = req.body;

    if (!amount || !payout_method || !account_details) {
        return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
    }

    const methodKey = payout_method.toLowerCase().trim();
    const methodConfig = PAYOUT_CONFIG[methodKey];

    if (!methodConfig) {
        return res.status(400).json({ error: 'Método de pago no válido.' });
    }

    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount < methodConfig.minAmount) {
        return res.status(400).json({ error: `El monto mínimo es $${methodConfig.minAmount.toFixed(2)} USD.` });
    }

    const userFee = (withdrawAmount * methodConfig.fixedFeePercent) + methodConfig.fixedFeeAmount;
    const finalAmountToSend = Math.max(0, withdrawAmount - userFee);

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const userResult = await client.query(
            'SELECT points_balance FROM web_users WHERE id = $1 FOR UPDATE',
            [userId]
        );

        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }

        const totalPoints = parseFloat(userResult.rows[0].points_balance) || 0;
        const availableBalance = totalPoints * POINT_TO_CURRENCY_RATIO;

        if (withdrawAmount > availableBalance) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Saldo insuficiente.' });
        }

        const insertQuery = `
            INSERT INTO withdrawal_requests (user_id, amount, payout_method, account_details)
            VALUES ($1, $2, $3, $4)
            RETURNING *;
        `;
        const newWithdrawal = await client.query(insertQuery, [
            userId, 
            withdrawAmount, 
            `${payout_method} (Neto: $${finalAmountToSend.toFixed(2)} USD - Fee: $${userFee.toFixed(2)})`, 
            account_details
        ]);

        const pointsToDeduct = Math.round(withdrawAmount / POINT_TO_CURRENCY_RATIO);

        await client.query(
            'UPDATE web_users SET points_balance = points_balance - $1 WHERE id = $2',
            [pointsToDeduct, userId]
        );

        await client.query('COMMIT');

        return res.status(201).json({
            message: 'Solicitud de retiro registrada con éxito.',
            withdrawal: newWithdrawal.rows[0],
            fee_applied: userFee.toFixed(2),
            net_amount: finalAmountToSend.toFixed(2)
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al procesar el retiro:', error);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    } finally {
        client.release();
    }
});

// Historial de Retiros
app.get('/api/withdrawals', verifyToken, async (req, res) => {
    try {
        const history = await db.query(
            'SELECT * FROM withdrawal_requests WHERE user_id = $1 ORDER BY created_at DESC',
            [req.user.userId]
        );
        return res.json({ withdrawals: history.rows });
    } catch (error) {
        console.error('Error al obtener retiros:', error);
        return res.status(500).json({ error: 'Error al consultar el historial.' });
    }
});

// Saldo y Datos de Perfil
app.get('/api/v1/user/profile', verifyToken, async (req, res) => {
    try {
        const userRes = await db.query(
            `SELECT id, email, binance_id, country_code, tier_level, points_balance, 
                    daily_videos_watched, referral_code, total_referrals 
             FROM web_users WHERE id = $1`, 
            [req.user.userId]
        );
        if (userRes.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado.' });
        return res.json({ success: true, user: userRes.rows[0] });
    } catch (err) {
        return res.status(500).json({ error: 'Error al obtener el perfil.' });
    }
});

// ==========================================
// RUTAS DE ADMINISTRACIÓN
// ==========================================
app.get('/api/admin/withdrawals/pending', verifyAdmin, async (req, res) => {
    try {
        const query = `
            SELECT w.*, u.email, u.binance_id
            FROM withdrawal_requests w
            LEFT JOIN web_users u ON w.user_id = u.id
            WHERE w.status = 'pending'
            ORDER BY w.created_at DESC
        `;
        const result = await db.query(query);
        return res.json({ withdrawals: result.rows });
    } catch (error) {
        console.error('Error al obtener retiros pendientes:', error);
        return res.status(500).json({ error: 'Error de consulta en base de datos.' });
    }
});

app.patch('/api/admin/withdrawals/:id', verifyAdmin, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    if (!['completed', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Estado inválido. Debe ser completed o rejected.' });
    }

    const client = await db.connect();

    try {
        await client.query('BEGIN');

        const checkResult = await client.query(
            'SELECT * FROM withdrawal_requests WHERE id = $1 FOR UPDATE', 
            [id]
        );

        if (checkResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Solicitud no encontrada.' });
        }

        const withdrawal = checkResult.rows[0];

        if (withdrawal.status !== 'pending') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: `La solicitud ya fue procesada como: ${withdrawal.status}` });
        }

        const result = await client.query(
            'UPDATE withdrawal_requests SET status = $1 WHERE id = $2 RETURNING *', 
            [status, id]
        );

        if (status === 'rejected') {
            const pointsToRefund = Math.round(parseFloat(withdrawal.amount) / POINT_TO_CURRENCY_RATIO);

            await client.query(
                'UPDATE web_users SET points_balance = points_balance + $1 WHERE id = $2',
                [pointsToRefund, withdrawal.user_id]
            );
        }

        await client.query('COMMIT');

        return res.json({ 
            message: `Solicitud #${id} marcada como ${status}.`, 
            withdrawal: result.rows[0] 
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Error al actualizar retiro:', error);
        return res.status(500).json({ error: 'Error al actualizar la solicitud.' });
    } finally {
        client.release();
    }
});

// Ruta base
app.get('/', (req, res) => {
    res.status(200).send('Servidor activo 🚀');
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor iniciado en puerto ${PORT}`));
