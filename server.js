const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const pool = require('./db');
const { sendSms } = require('./sms');

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ==========================================
// בדיקת הגדרות חובה - השרת לא יעלה בלעדיהן
// ==========================================
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('JWT_SECRET is missing or too short in .env - server will not start');
    process.exit(1);
}

const app = express();

// מאחורי שרת אחסון (Render / Railway וכו') - כדי שהגבלת הבקשות תזהה את ה-IP האמיתי
if (IS_PRODUCTION) {
    app.set('trust proxy', 1);
}

// ==========================================
// דף האדמין - מוגש מהשרת בכתובת /admin (הקובץ admin.html צריך לשבת ליד server.js)
// מוגש לפני helmet כי הדף משתמש בספריות מ-CDN. הכניסה אליו מוגנת בסיסמה (ראה /api/admin/login)
// ==========================================
app.get('/admin', (req, res) => {
    res.set({
        'Cache-Control': 'no-store',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'X-Robots-Tag': 'noindex, nofollow',
        'Referrer-Policy': 'no-referrer'
    });
    res.sendFile(path.join(__dirname, 'admin.html'), (err) => {
        if (err && !res.headersSent) res.status(404).end();
    });
});

// ==========================================
// Middlewares של אבטחה
// ==========================================

// כותרות אבטחה סטנדרטיות (מסתיר שהשרת הוא Express, מונע הטמעה באתרים זרים וכו')
app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' } // כדי שתמונות המוצרים ייטענו באפליקציה
}));

// CORS - רק כתובות שמופיעות ב-ALLOWED_ORIGINS יכולות לפנות לשרת מדפדפן
// אפליקציה נייטיב (iOS/Android) לא שולחת Origin, ולכן היא תמיד מורשית
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

if (IS_PRODUCTION && allowedOrigins.length === 0) {
    console.warn('ALLOWED_ORIGINS is empty - browser requests from any website will be blocked');
}

app.use((req, res, next) => cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);                    // אפליקציה / Postman
        if (origin === `${req.protocol}://${req.get('host')}`) return callback(null, true); // דף האדמין שמוגש מהשרת עצמו
        if (!IS_PRODUCTION && allowedOrigins.length === 0) return callback(null, true); // פיתוח מקומי
        if (allowedOrigins.includes(origin)) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
    }
})(req, res, next));

// הגבלת גודל גוף הבקשה
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// הגבלת בקשות כללית לכל ה-API
// (נדיב, כי הרבה תלמידים יוצאים לאינטרנט מאותו IP של בית הספר)
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 1000,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many requests. Try again later' }
});
app.use('/api', generalLimiter);

// הגבלה קשוחה יותר לנתיבי התחברות והרשמה - מונעת ניחוש סיסמאות וקודים
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 50,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many attempts. Try again in a few minutes' }
});

const managerLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many login attempts. Try again in 15 minutes' }
});

// ==========================================
// תמונות מוצרים - נשמרות בתוך מסד הנתונים (עמודות image_data, image_mime בטבלת products)
// בשרת ענן כמו Railway הדיסק נמחק בכל עדכון גרסה, ולכן לא שומרים תמונות בתיקייה
// ==========================================

// רק קבצי תמונה, עד 5MB
const ALLOWED_IMAGE_TYPES = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp'
};

// הקובץ נשאר בזיכרון (req.file.buffer) ומשם נכתב למסד הנתונים
const storage = multer.memoryStorage();

// כתובת מלאה לתמונה של מוצר (למשל https://sixeven.up.railway.app/images/products/7)
function productImageUrl(req, productId) {
    return `${req.protocol}://${req.get('host')}/images/products/${productId}`;
}

// הגשת תמונת מוצר מתוך המסד - ציבורי.
// נמצא מחוץ ל-/api כדי שטעינת תפריט עם הרבה תמונות לא תיספר בהגבלת הבקשות
app.get('/images/products/:id', async (req, res) => {
    const productId = Number(req.params.id);
    if (!Number.isInteger(productId) || productId < 1) {
        return res.status(404).end();
    }

    try {
        const result = await pool.query(
            'SELECT image_data, image_mime FROM products WHERE id = $1 AND image_data IS NOT NULL',
            [productId]
        );

        if (result.rows.length === 0) {
            return res.status(404).end();
        }

        const { image_data, image_mime } = result.rows[0];
        res.set('Content-Type', ALLOWED_IMAGE_TYPES[image_mime] ? image_mime : 'application/octet-stream');
        res.set('Cache-Control', 'public, max-age=86400'); // הדפדפן שומר את התמונה ליום
        res.send(image_data);

    } catch (err) {
        console.error('Error fetching product image:', err);
        res.status(500).end();
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024, files: 1 },
    fileFilter: (req, file, cb) => {
        if (ALLOWED_IMAGE_TYPES[file.mimetype]) {
            cb(null, true);
        } else {
            cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'image'));
        }
    }
});

// ==========================================
// הגדרות כניסה עם קוד SMS
// ==========================================
const OTP_TTL_MINUTES = 5;          // תוקף הקוד
const OTP_MAX_ATTEMPTS = 5;         // כמה ניסיונות שגויים מותר לכל קוד
const OTP_RESEND_SECONDS = 60;      // זמן המתנה מינימלי בין שליחות
const OTP_MAX_PER_HOUR = 5;         // מקסימום קודים לתלמיד בשעה

// מצב פיילוט: אם משתנה הסביבה PILOT_FIXED_CODE מוגדר (6 ספרות, למשל 111111),
// כל התלמידים נכנסים עם הקוד הקבוע הזה ולא נשלח SMS.
// כדי לחזור לקודים אמיתיים - פשוט מוחקים את המשתנה (ב-Render: Environment) ולא צריך לשנות קוד.
const PILOT_FIXED_CODE = /^\d{6}$/.test(process.env.PILOT_FIXED_CODE || '')
    ? process.env.PILOT_FIXED_CODE
    : null;
if (PILOT_FIXED_CODE) {
    console.warn('PILOT MODE: fixed student login code is active - anyone who knows a student name + phone can log in as them');
}

const STUDENT_TOKEN_TTL = '30d';
const MANAGER_TOKEN_TTL = '12h';

// ניקוי מספר טלפון לפורמט אחיד: ספרות בלבד, מתחיל ב-0 (למשל 0501234567)
function normalizePhone(phone) {
    let digits = String(phone).replace(/\D/g, '');
    if (digits.startsWith('972')) {
        digits = '0' + digits.slice(3);
    }
    return digits;
}

// מספר נייד ישראלי: 05 ועוד 8 ספרות
function isValidPhone(phone) {
    return /^05\d{8}$/.test(phone);
}

function cleanText(value, maxLength) {
    if (value === undefined || value === null) return null;
    const text = String(value).trim();
    return text ? text.slice(0, maxLength) : null;
}

function hashCode(code) {
    return crypto.createHash('sha256').update(String(code)).digest('hex');
}

// השוואה בטוחה (לא חושפת מידע דרך זמן התגובה)
function safeEqual(a, b) {
    const bufA = Buffer.from(String(a));
    const bufB = Buffer.from(String(b));
    return bufA.length === bufB.length && crypto.timingSafeEqual(bufA, bufB);
}

// ==========================================
// שעות פתיחה אוטומטיות
// עמודות: auto_schedule (האם הפתיחה אוטומטית) ו-schedule (JSON לפי יום, 0=ראשון עד 6=שבת)
//   { "0": { "enabled": true, "open": "07:30", "close": "14:00" }, ... }
// במצב אוטומטי הקפיטריה פתוחה רק ביום מופעל ובין שעת הפתיחה לשעת הסגירה (שעון ישראל).
// במצב ידני (auto_schedule = FALSE) נשארת הפתיחה/נעילה הידנית (is_open) כמו קודם.
// ==========================================
const DAY_INDEX = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

function israelNow() {
    const parts = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Asia/Jerusalem', weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
    }).formatToParts(new Date());
    const get = (t) => parts.find(p => p.type === t).value;
    return { day: DAY_INDEX[get('weekday')], time: `${get('hour')}:${get('minute')}` };
}

function isCafeteriaOpenNow(row) {
    if (!row) return false;
    if (!row.auto_schedule) return !!row.is_open;
    const schedule = row.schedule || {};
    const { day, time } = israelNow();
    const d = schedule[String(day)];
    return !!(d && d.enabled && TIME_RE.test(d.open) && TIME_RE.test(d.close) && time >= d.open && time < d.close);
}

function validateSchedule(input) {
    if (!input || typeof input !== 'object') return null;
    const out = {};
    for (let i = 0; i < 7; i++) {
        const d = input[String(i)];
        if (!d || typeof d !== 'object') return null;
        const enabled = d.enabled === true;
        if (enabled && (!TIME_RE.test(d.open) || !TIME_RE.test(d.close) || d.open >= d.close)) return null;
        out[String(i)] = {
            enabled,
            open: TIME_RE.test(d.open) ? d.open : '07:30',
            close: TIME_RE.test(d.close) ? d.close : '14:00'
        };
    }
    return out;
}

// ==========================================
// בדיקת התחברות
// הלקוח שולח: Authorization: Bearer <token>
// ==========================================
function readToken(req) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
        return null;
    }
}

// נתיבים של תלמיד מחובר
function requireStudent(req, res, next) {
    const payload = readToken(req);
    if (!payload || payload.role !== 'student') {
        return res.status(401).json({ status: 'error', message: 'Please log in again' });
    }
    req.student = payload;
    next();
}

// נתיבים של מנהל קפיטריה מחובר
function requireCafeteria(req, res, next) {
    const payload = readToken(req);
    if (!payload || payload.role !== 'cafeteria') {
        return res.status(401).json({ status: 'error', message: 'Manager login required' });
    }
    req.cafeteria = payload;
    next();
}

// ==========================================
// בדיקת תקינות שרת
// ==========================================
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'ok' });
    } catch (err) {
        console.error('Database connection error:', err);
        res.status(500).json({ status: 'error', message: 'Database connection failed' });
    }
});

// ==========================================
// 1. רישום תלמיד לקפיטריה
// ==========================================
app.post('/api/students/register', authLimiter, async (req, res) => {
    const name = cleanText(req.body.name, 50);
    const cafeteriaName = cleanText(req.body.cafeteriaName, 100);
    const phone = req.body.phone ? normalizePhone(req.body.phone) : null;

    if (!name || !phone || !cafeteriaName) {
        return res.status(400).json({
            status: 'error',
            message: 'Name, phone, and cafeteriaName are required'
        });
    }

    // חובה לאשר את תנאי השימוש. הדיוור השיווקי הוא רשות ונשמר רק אם סומן במפורש
    if (req.body.acceptedTerms !== true) {
        return res.status(400).json({
            status: 'error',
            message: 'You must accept the terms of use'
        });
    }
    const termsVersion = cleanText(req.body.termsVersion, 20);
    const marketingConsent = req.body.marketingConsent === true;

    if (!isValidPhone(phone)) {
        return res.status(400).json({
            status: 'error',
            message: 'Phone must be an Israeli mobile number (05XXXXXXXX)'
        });
    }

    try {
        const cafeteriaResult = await pool.query(
            'SELECT id FROM cafeterias WHERE name = $1',
            [cafeteriaName]
        );

        if (cafeteriaResult.rows.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'Cafeteria not found'
            });
        }

        const cafeteria_id = cafeteriaResult.rows[0].id;

        // אותו מספר טלפון לא יכול להירשם פעמיים
        const existing = await pool.query(
            `SELECT id FROM students WHERE regexp_replace(phone, '\\D', '', 'g') = $1`,
            [phone]
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({
                status: 'error',
                message: 'This phone number is already registered'
            });
        }

        const result = await pool.query(
            `INSERT INTO students (name, phone, cafeteria_id, terms_accepted_at, terms_version, marketing_consent, marketing_consent_at)
             VALUES ($1, $2, $3, NOW(), $4, $5, CASE WHEN $5 THEN NOW() ELSE NULL END)
             RETURNING id, name, phone, cafeteria_id`,
            [name, phone, cafeteria_id, termsVersion, marketingConsent]
        );

        res.status(201).json({
            status: 'success',
            message: 'Student registered successfully!',
            student: result.rows[0]
        });

    } catch (err) {
        console.error('Error registering student:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while registering student'
        });
    }
});

// ==========================================
// 1א. כניסת תלמיד - שלב 1: בקשת קוד ב-SMS
// גוף הבקשה: { name, phone }
// ==========================================
app.post('/api/students/login/request-code', authLimiter, async (req, res) => {
    const name = cleanText(req.body.name, 50);
    const phone = req.body.phone ? normalizePhone(req.body.phone) : null;

    if (!name || !phone) {
        return res.status(400).json({
            status: 'error',
            message: 'Name and phone are required'
        });
    }

    if (!isValidPhone(phone)) {
        return res.status(400).json({
            status: 'error',
            message: 'Phone must be an Israeli mobile number (05XXXXXXXX)'
        });
    }

    try {
        // חיפוש התלמיד לפי טלפון + שם (מתעלם מרווחים/מקפים בטלפון השמור)
        const studentResult = await pool.query(
            `SELECT id, name, phone
             FROM students
             WHERE regexp_replace(phone, '\\D', '', 'g') = $1
               AND LOWER(TRIM(name)) = LOWER($2)
             ORDER BY id
             LIMIT 1`,
            [phone, name]
        );

        if (studentResult.rows.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'No student found with this name and phone'
            });
        }

        const student = studentResult.rows[0];

        // הגבלת קצב שליחה - מונע הצפת SMS (ועלויות)
        const recentResult = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') AS last_hour,
                MAX(created_at) AS last_sent
             FROM otp_codes
             WHERE student_id = $1`,
            [student.id]
        );
        const { last_hour, last_sent } = recentResult.rows[0];

        if (last_sent && (Date.now() - new Date(last_sent).getTime()) < OTP_RESEND_SECONDS * 1000) {
            return res.status(429).json({
                status: 'error',
                message: `Please wait ${OTP_RESEND_SECONDS} seconds before requesting a new code`
            });
        }

        if (Number(last_hour) >= OTP_MAX_PER_HOUR) {
            return res.status(429).json({
                status: 'error',
                message: 'Too many codes requested. Try again later'
            });
        }

        // יצירת קוד אקראי של 6 ספרות (100000-999999)
        // (במצב פיילוט - הקוד הקבוע)
        const code = PILOT_FIXED_CODE || crypto.randomInt(100000, 1000000).toString();

        // ביטול קודים קודמים שעוד לא נוצלו, ושמירת הקוד החדש
        await pool.query(
            'UPDATE otp_codes SET used = TRUE WHERE student_id = $1 AND used = FALSE',
            [student.id]
        );
        await pool.query(
            `INSERT INTO otp_codes (student_id, code_hash, expires_at)
             VALUES ($1, $2, NOW() + ($3 || ' minutes')::INTERVAL)`,
            [student.id, hashCode(code), OTP_TTL_MINUTES]
        );

        if (!PILOT_FIXED_CODE) {
            await sendSms(student.phone, `קוד הכניסה שלך ל-siXeven: ${code}\nהקוד תקף ל-${OTP_TTL_MINUTES} דקות.`);
        }

        res.status(200).json({
            status: 'success',
            message: 'Verification code sent',
            expiresInMinutes: OTP_TTL_MINUTES
        });

    } catch (err) {
        console.error('Error sending login code:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while sending login code'
        });
    }
});

// ==========================================
// 1ב. כניסת תלמיד - שלב 2: אימות הקוד
// גוף הבקשה: { phone, code }
// מחזיר token שהאפליקציה שומרת ושולחת בכל בקשה (Authorization: Bearer ...)
// ==========================================
app.post('/api/students/login/verify-code', authLimiter, async (req, res) => {
    const phone = req.body.phone ? normalizePhone(req.body.phone) : null;
    const code = req.body.code ? String(req.body.code).trim() : null;

    if (!phone || !code) {
        return res.status(400).json({
            status: 'error',
            message: 'Phone and code are required'
        });
    }

    if (!/^\d{6}$/.test(code)) {
        return res.status(400).json({
            status: 'error',
            message: 'Code must be 6 digits'
        });
    }

    try {
        // הקוד הפעיל האחרון של תלמיד עם מספר הטלפון הזה
        const otpResult = await pool.query(
            `SELECT o.id, o.code_hash, o.attempts, o.expires_at,
                    s.id AS student_id, s.name, s.phone, s.cafeteria_id, s.balance
             FROM otp_codes o
             JOIN students s ON s.id = o.student_id
             WHERE regexp_replace(s.phone, '\\D', '', 'g') = $1
               AND o.used = FALSE
             ORDER BY o.created_at DESC
             LIMIT 1`,
            [phone]
        );

        if (otpResult.rows.length === 0) {
            return res.status(400).json({
                status: 'error',
                message: 'No active code. Please request a new one'
            });
        }

        const otp = otpResult.rows[0];

        if (new Date(otp.expires_at) < new Date()) {
            await pool.query('UPDATE otp_codes SET used = TRUE WHERE id = $1', [otp.id]);
            return res.status(400).json({
                status: 'error',
                message: 'Code expired. Please request a new one'
            });
        }

        if (otp.attempts >= OTP_MAX_ATTEMPTS) {
            await pool.query('UPDATE otp_codes SET used = TRUE WHERE id = $1', [otp.id]);
            return res.status(429).json({
                status: 'error',
                message: 'Too many wrong attempts. Please request a new code'
            });
        }

        if (!safeEqual(hashCode(code), otp.code_hash)) {
            await pool.query('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1', [otp.id]);
            return res.status(401).json({
                status: 'error',
                message: 'Wrong code',
                attemptsLeft: OTP_MAX_ATTEMPTS - otp.attempts - 1
            });
        }

        // קוד נכון - מסמנים כמנוצל ומנפיקים token
        await pool.query('UPDATE otp_codes SET used = TRUE WHERE id = $1', [otp.id]);

        const token = jwt.sign(
            { role: 'student', studentId: otp.student_id, cafeteriaId: otp.cafeteria_id },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: STUDENT_TOKEN_TTL }
        );

        res.status(200).json({
            status: 'success',
            message: 'Logged in successfully!',
            token,
            student: {
                id: otp.student_id,
                name: otp.name,
                phone: otp.phone,
                cafeteria_id: otp.cafeteria_id,
                balance: Number(otp.balance || 0)
            }
        });

    } catch (err) {
        console.error('Error verifying login code:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while verifying code'
        });
    }
});

// ==========================================
// 1ג. פרטי התלמיד המחובר
// ==========================================
app.get('/api/students/me', requireStudent, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.id, s.name, s.phone, s.cafeteria_id, COALESCE(s.balance, 0) AS balance, COALESCE(s.marketing_consent, FALSE) AS marketing_consent, c.name AS cafeteria_name
             FROM students s
             JOIN cafeterias c ON c.id = s.cafeteria_id
             WHERE s.id = $1`,
            [req.student.studentId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Student not found' });
        }

        res.status(200).json({ status: 'success', student: result.rows[0] });

    } catch (err) {
        console.error('Error fetching student:', err);
        res.status(500).json({ status: 'error', message: 'Server error while fetching student' });
    }
});

// ==========================================
// ביטול / חידוש הסכמה לדיוור שיווקי (התלמיד המחובר)
// ==========================================
app.put('/api/students/marketing', requireStudent, async (req, res) => {
    if (typeof req.body.marketingConsent !== 'boolean') {
        return res.status(400).json({ status: 'error', message: 'marketingConsent must be true or false' });
    }
    try {
        const result = await pool.query(
            `UPDATE students SET marketing_consent = $1, marketing_consent_at = NOW()
             WHERE id = $2 RETURNING marketing_consent`,
            [req.body.marketingConsent, req.student.studentId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Student not found' });
        }
        res.status(200).json({ status: 'success', marketing_consent: result.rows[0].marketing_consent });
    } catch (err) {
        console.error('Error updating marketing consent:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating consent' });
    }
});

// ==========================================
// טעינת ארנק לתלמיד לפי מספר טלפון - מנהל קפיטריה מחובר בלבד
// GET  /api/cafeteria/students/lookup?phone=05XXXXXXXX  -> שם התלמיד (לאימות לפני טעינה)
// POST /api/cafeteria/topup  { phone, amount }
// אפשר לטעון רק לתלמיד ששייך לקפיטריה של המנהל המחובר
// ==========================================
app.get('/api/cafeteria/students/lookup', requireCafeteria, async (req, res) => {
    const phone = normalizePhone(req.query.phone || '');
    if (!isValidPhone(phone)) {
        return res.status(400).json({ status: 'error', message: 'Phone must be an Israeli mobile number (05XXXXXXXX)' });
    }
    try {
        const result = await pool.query(
            'SELECT name FROM students WHERE phone = $1 AND cafeteria_id = $2',
            [phone, req.cafeteria.cafeteriaId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'No student with this phone in your cafeteria' });
        }
        res.status(200).json({ status: 'success', name: result.rows[0].name });
    } catch (err) {
        console.error('Error looking up student:', err);
        res.status(500).json({ status: 'error', message: 'Server error while looking up student' });
    }
});

app.post('/api/cafeteria/topup', requireCafeteria, async (req, res) => {
    const phone = normalizePhone(req.body.phone || '');
    const amount = Math.round(Number(req.body.amount) * 100) / 100;

    if (!isValidPhone(phone)) {
        return res.status(400).json({ status: 'error', message: 'Phone must be an Israeli mobile number (05XXXXXXXX)' });
    }
    if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ status: 'error', message: 'Amount must be greater than 0' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const studentResult = await client.query(
            'SELECT id, name FROM students WHERE phone = $1 AND cafeteria_id = $2 FOR UPDATE',
            [phone, req.cafeteria.cafeteriaId]
        );
        if (studentResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ status: 'error', message: 'No student with this phone in your cafeteria' });
        }
        const student = studentResult.rows[0];

        const updated = await client.query(
            'UPDATE students SET balance = COALESCE(balance, 0) + $1 WHERE id = $2 RETURNING balance',
            [amount, student.id]
        );

        await client.query(
            `INSERT INTO balance_transactions (student_id, amount, type, description)
             VALUES ($1, $2, 'topup', $3)`,
            [student.id, amount, `טעינה על ידי הקפיטריה (מנהל ${req.cafeteria.cafeteriaId})`]
        );

        await client.query('COMMIT');
        res.status(200).json({
            status: 'success',
            student_name: student.name,
            added: amount,
            newBalance: Number(updated.rows[0].balance)
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error topping up wallet:', err);
        res.status(500).json({ status: 'error', message: 'Server error while topping up wallet' });
    } finally {
        client.release();
    }
});

// ==========================================
// אדמין (בעל האפליקציה) - /api/admin/*
// הסיסמה לא נשמרת בקוד ולא במסד: ב-Render מגדירים משתנה סביבה ADMIN_PASSWORD_HASH
// (גיבוב bcrypt של הסיסמה). אם המשתנה לא מוגדר - האדמין כבוי לגמרי.
// ==========================================
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const ADMIN_TOKEN_TTL = '2h';
if (!ADMIN_PASSWORD_HASH.startsWith('$2')) {
    console.warn('ADMIN_PASSWORD_HASH is not set - admin panel is disabled');
}

const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many login attempts. Try again in 15 minutes' }
});

function requireAdmin(req, res, next) {
    const payload = readToken(req);
    if (!payload || payload.role !== 'admin') {
        return res.status(401).json({ status: 'error', message: 'Admin login required' });
    }
    next();
}

app.post('/api/admin/login', adminLoginLimiter, async (req, res) => {
    if (!ADMIN_PASSWORD_HASH.startsWith('$2')) {
        return res.status(503).json({ status: 'error', message: 'Admin is not configured' });
    }
    const password = req.body.password ? String(req.body.password) : '';
    try {
        const ok = password.length > 0 && await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        if (!ok) {
            return res.status(401).json({ status: 'error', message: 'Invalid login details' });
        }
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { algorithm: 'HS256', expiresIn: ADMIN_TOKEN_TTL });
        res.status(200).json({ status: 'success', token });
    } catch (err) {
        console.error('Error during admin login:', err);
        res.status(500).json({ status: 'error', message: 'Server error during login' });
    }
});

// תחילת התקופה לפי שעון ישראל (ערכים קבועים מראש - לא נכנס קלט של משתמש ל-SQL)
const ADMIN_PERIODS = {
    today: "o.created_at >= (date_trunc('day', NOW() AT TIME ZONE 'Asia/Jerusalem') AT TIME ZONE 'Asia/Jerusalem')",
    '7d':  "o.created_at >= NOW() - INTERVAL '7 days'",
    '30d': "o.created_at >= NOW() - INTERVAL '30 days'",
    all:   "TRUE"
};

// סקירה: נתוני כל הקפיטריות לתקופה
app.get('/api/admin/overview', requireAdmin, async (req, res) => {
    const periodSql = ADMIN_PERIODS[req.query.period] || ADMIN_PERIODS.today;
    try {
        const result = await pool.query(
            `SELECT c.id, c.name, c.email, COALESCE(c.is_open, FALSE) AS is_open, COALESCE(c.auto_schedule, FALSE) AS auto_schedule, c.schedule,
                    (SELECT COUNT(*) FROM students s WHERE s.cafeteria_id = c.id)::int AS students,
                    COUNT(o.id) FILTER (WHERE o.status <> 'cancelled')::int AS orders,
                    COUNT(o.id) FILTER (WHERE o.status = 'pending')::int AS pending,
                    COUNT(o.id) FILTER (WHERE o.status = 'cancelled')::int AS cancelled,
                    COALESCE(SUM(o.total_price) FILTER (WHERE o.status <> 'cancelled'), 0) AS revenue,
                    COALESCE(SUM(o.total_price) FILTER (WHERE o.status <> 'cancelled' AND o.payment_method = 'cash'), 0) AS cash_total,
                    COALESCE(SUM(o.total_price) FILTER (WHERE o.status <> 'cancelled' AND o.payment_method IS DISTINCT FROM 'cash'), 0) AS wallet_total
             FROM cafeterias c
             LEFT JOIN orders o ON o.cafeteria_id = c.id AND ${periodSql}
             GROUP BY c.id
             ORDER BY c.name`
        );
        const cafeterias = result.rows.map(({ schedule, ...r }) => ({
            ...r,
            is_open: isCafeteriaOpenNow({ ...r, schedule }),
            revenue: Number(r.revenue),
            cash_total: Number(r.cash_total),
            wallet_total: Number(r.wallet_total)
        }));
        const totals = cafeterias.reduce((t, c) => ({
            orders: t.orders + c.orders,
            pending: t.pending + c.pending,
            revenue: t.revenue + c.revenue,
            cash_total: t.cash_total + c.cash_total,
            wallet_total: t.wallet_total + c.wallet_total,
            students: t.students + c.students
        }), { orders: 0, pending: 0, revenue: 0, cash_total: 0, wallet_total: 0, students: 0 });

        res.status(200).json({ status: 'success', totals, cafeterias });
    } catch (err) {
        console.error('Error building admin overview:', err);
        res.status(500).json({ status: 'error', message: 'Server error while loading overview' });
    }
});

// הזמנות של כל הקפיטריות, עם סינון
app.get('/api/admin/orders', requireAdmin, async (req, res) => {
    const periodSql = ADMIN_PERIODS[req.query.period] || ADMIN_PERIODS.today;
    const conditions = [periodSql];
    const params = [];

    const cafeteriaId = Number(req.query.cafeteriaId);
    if (Number.isInteger(cafeteriaId) && cafeteriaId > 0) {
        params.push(cafeteriaId);
        conditions.push(`o.cafeteria_id = $${params.length}`);
    }
    if (['pending', 'ready', 'cancelled'].includes(req.query.status)) {
        params.push(req.query.status);
        conditions.push(`o.status = $${params.length}`);
    }
    if (req.query.payment === 'cash') conditions.push("o.payment_method = 'cash'");
    if (req.query.payment === 'wallet') conditions.push("o.payment_method IS DISTINCT FROM 'cash'");

    try {
        const result = await pool.query(
            `SELECT o.id, o.status, o.total_price, o.notes, o.payment_method, o.picked_up_at, o.created_at,
                    c.id AS cafeteria_id, c.name AS cafeteria_name,
                    s.name AS student_name, s.phone AS student_phone,
                    COALESCE(
                        json_agg(
                            json_build_object('product_name', p.name, 'quantity', oi.quantity, 'item_notes', oi.item_notes)
                            ORDER BY oi.id
                        ) FILTER (WHERE oi.id IS NOT NULL),
                        '[]'
                    ) AS items
             FROM orders o
             JOIN cafeterias c ON c.id = o.cafeteria_id
             JOIN students s ON s.id = o.student_id
             LEFT JOIN order_items oi ON oi.order_id = o.id
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE ${conditions.join(' AND ')}
             GROUP BY o.id, c.id, s.id
             ORDER BY o.created_at DESC
             LIMIT 300`,
            params
        );
        res.status(200).json({ status: 'success', count: result.rows.length, orders: result.rows });
    } catch (err) {
        console.error('Error fetching admin orders:', err);
        res.status(500).json({ status: 'error', message: 'Server error while fetching orders' });
    }
});

// יצירת קפיטריה חדשה
app.post('/api/admin/cafeterias', requireAdmin, async (req, res) => {
    const name = cleanText(req.body.name, 100);
    const email = cleanText(req.body.email, 200);
    const password = req.body.password ? String(req.body.password) : '';

    if (!name || name.length < 2) {
        return res.status(400).json({ status: 'error', message: 'Cafeteria name is required (2+ characters)' });
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ status: 'error', message: 'A valid email is required' });
    }
    if (password.length < 8) {
        return res.status(400).json({ status: 'error', message: 'Password must be at least 8 characters' });
    }

    try {
        const exists = await pool.query('SELECT 1 FROM cafeterias WHERE LOWER(name) = LOWER($1)', [name]);
        if (exists.rows.length > 0) {
            return res.status(409).json({ status: 'error', message: 'A cafeteria with this name already exists' });
        }
        const hashed = await bcrypt.hash(password, 12);
        const result = await pool.query(
            'INSERT INTO cafeterias (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
            [name, email, hashed]
        );
        res.status(201).json({ status: 'success', cafeteria: result.rows[0] });
    } catch (err) {
        console.error('Error creating cafeteria:', err);
        res.status(500).json({ status: 'error', message: 'Server error while creating cafeteria' });
    }
});

// איפוס סיסמת מנהל של קפיטריה
app.put('/api/admin/cafeterias/:id/password', requireAdmin, async (req, res) => {
    const id = Number(req.params.id);
    const password = req.body.password ? String(req.body.password) : '';
    if (!Number.isInteger(id) || id < 1) {
        return res.status(400).json({ status: 'error', message: 'Invalid cafeteria id' });
    }
    if (password.length < 8) {
        return res.status(400).json({ status: 'error', message: 'Password must be at least 8 characters' });
    }
    try {
        const hashed = await bcrypt.hash(password, 12);
        const result = await pool.query('UPDATE cafeterias SET password = $1 WHERE id = $2 RETURNING id', [hashed, id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Cafeteria not found' });
        }
        res.status(200).json({ status: 'success' });
    } catch (err) {
        console.error('Error resetting cafeteria password:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating password' });
    }
});

// ==========================================
// שליפת שמות כל הקפיטריות (למסך הבית) - ציבורי
// ==========================================
app.get('/api/cafeterias', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name FROM cafeterias ORDER BY name'
        );

        res.status(200).json({
            status: 'success',
            count: result.rows.length,
            cafeterias: result.rows
        });

    } catch (err) {
        console.error('Error fetching cafeterias:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while fetching cafeterias'
        });
    }
});

// ==========================================
// 2. התחברות מנהל קפיטריה
// מחזיר token שהאפליקציה של המנהל שולחת בכל בקשה (Authorization: Bearer ...)
// ==========================================
app.post('/api/cafeterias/login', managerLoginLimiter, async (req, res) => {
    const cafeteriaName = cleanText(req.body.cafeteriaName, 100);
    const email = cleanText(req.body.email, 200);
    const password = req.body.password ? String(req.body.password) : null;

    if (!cafeteriaName || !email || !password) {
        return res.status(400).json({
            status: 'error',
            message: 'Cafeteria name, email, and password are required'
        });
    }

    // הודעה אחת לכל סוגי הכישלון - לא מגלים אם הקפיטריה, האימייל או הסיסמה שגויים
    const invalid = () => res.status(401).json({
        status: 'error',
        message: 'Invalid login details'
    });

    try {
        const result = await pool.query(
            'SELECT id, name, email, password FROM cafeterias WHERE name = $1',
            [cafeteriaName]
        );

        if (result.rows.length === 0) {
            return invalid();
        }

        const cafeteria = result.rows[0];

        if (String(cafeteria.email).toLowerCase() !== email.toLowerCase()) {
            return invalid();
        }

        const stored = String(cafeteria.password || '');
        let passwordOk = false;

        if (stored.startsWith('$2')) {
            // סיסמה מוצפנת (bcrypt)
            passwordOk = await bcrypt.compare(password, stored);
        } else {
            // סיסמה ישנה שנשמרה כטקסט רגיל - בודקים, ואם נכונה מצפינים אותה מיד
            passwordOk = stored.length > 0 && safeEqual(password, stored);
            if (passwordOk) {
                try {
                    const hashed = await bcrypt.hash(password, 12);
                    await pool.query('UPDATE cafeterias SET password = $1 WHERE id = $2', [hashed, cafeteria.id]);
                } catch (upgradeErr) {
                    // הכניסה עדיין מצליחה; כנראה עמודת password קצרה מדי (צריך לפחות 60 תווים)
                    console.error('Could not encrypt cafeteria password:', upgradeErr.message);
                }
            }
        }

        if (!passwordOk) {
            return invalid();
        }

        const token = jwt.sign(
            { role: 'cafeteria', cafeteriaId: cafeteria.id },
            JWT_SECRET,
            { algorithm: 'HS256', expiresIn: MANAGER_TOKEN_TTL }
        );

        res.status(200).json({
            status: 'success',
            message: 'Cafeteria manager logged in successfully!',
            token,
            cafeteria: {
                id: cafeteria.id,
                name: cafeteria.name,
                email: cafeteria.email
            }
        });

    } catch (err) {
        console.error('Error during cafeteria login:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error during login'
        });
    }
});

// ==========================================
// 3. הוספת מוצר חדש - מנהל מחובר בלבד (תמונה היא רשות)
// המוצר נוסף לקפיטריה של המנהל המחובר
// ==========================================
app.post('/api/products', requireCafeteria, upload.single('image'), async (req, res) => {
    const cafeteria_id = req.cafeteria.cafeteriaId;
    const name = cleanText(req.body.name, 100);
    const description = cleanText(req.body.description, 500);
    const categoryName = cleanText(req.body.categoryName, 100);
    const price = Number(req.body.price);
    const { is_available } = req.body;

    if (!name || !Number.isFinite(price) || price <= 0 || price > 10000) {
        return res.status(400).json({
            status: 'error',
            message: 'name and a valid price are required'
        });
    }

    try {
        let category_id = null;
        if (categoryName) {
            const categoryResult = await pool.query(
                'SELECT id FROM categories WHERE name = $1',
                [categoryName]
            );

            if (categoryResult.rows.length === 0) {
                return res.status(404).json({
                    status: 'error',
                    message: `Category '${categoryName}' not found`
                });
            }

            category_id = categoryResult.rows[0].id;
        }

        // התמונה עצמה נשמרת במסד; image_url נשאר ריק ונבנה בזמן השליפה
        const imageData = req.file ? req.file.buffer : null;
        const imageMime = req.file ? req.file.mimetype : null;

        const result = await pool.query(
            `INSERT INTO products (cafeteria_id, name, price, description, is_available, category_id, image_data, image_mime)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, cafeteria_id, name, price, description, is_available, category_id,
                       (image_data IS NOT NULL) AS has_image`,
            [
                cafeteria_id,
                name,
                Math.round(price * 100) / 100,
                description,
                is_available !== undefined ? (is_available === 'true' || is_available === true) : true,
                category_id,
                imageData,
                imageMime
            ]
        );

        const { has_image, ...product } = result.rows[0];
        product.image_url = has_image ? productImageUrl(req, product.id) : null;

        res.status(201).json({
            status: 'success',
            message: 'Product added successfully!',
            product
        });

    } catch (err) {
        console.error('Error adding product:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while adding product'
        });
    }
});

// ==========================================
// עריכת מוצר - מנהל מחובר בלבד, ורק מוצר של הקפיטריה שלו
// PUT /api/products/:id  (multipart: name, price, description, categoryName, is_available, image, remove_image)
// שדה שלא נשלח - נשאר כמו שהוא. image חדש מחליף תמונה; remove_image=true מוחק את התמונה.
// ==========================================
app.put('/api/products/:id', requireCafeteria, upload.single('image'), async (req, res) => {
    const productId = Number(req.params.id);
    const cafeteria_id = req.cafeteria.cafeteriaId;
    if (!Number.isInteger(productId) || productId < 1) {
        return res.status(400).json({ status: 'error', message: 'Invalid product id' });
    }

    const sets = [];
    const params = [];
    const add = (column, value) => { params.push(value); sets.push(`${column} = $${params.length}`); };

    if (req.body.name !== undefined) {
        const name = cleanText(req.body.name, 100);
        if (!name) return res.status(400).json({ status: 'error', message: 'name cannot be empty' });
        add('name', name);
    }
    if (req.body.price !== undefined) {
        const price = Number(req.body.price);
        if (!Number.isFinite(price) || price <= 0 || price > 10000) {
            return res.status(400).json({ status: 'error', message: 'A valid price is required' });
        }
        add('price', Math.round(price * 100) / 100);
    }
    if (req.body.description !== undefined) add('description', cleanText(req.body.description, 500));
    if (req.body.is_available !== undefined) add('is_available', req.body.is_available === 'true' || req.body.is_available === true);

    try {
        const categoryName = cleanText(req.body.categoryName, 100);
        if (categoryName) {
            const cat = await pool.query('SELECT id FROM categories WHERE name = $1', [categoryName]);
            if (cat.rows.length === 0) {
                return res.status(404).json({ status: 'error', message: `Category '${categoryName}' not found` });
            }
            add('category_id', cat.rows[0].id);
        }

        if (req.file) {
            add('image_data', req.file.buffer);
            add('image_mime', req.file.mimetype);
        } else if (req.body.remove_image === 'true') {
            sets.push('image_data = NULL', 'image_mime = NULL');
        }

        if (sets.length === 0) {
            return res.status(400).json({ status: 'error', message: 'Nothing to update' });
        }

        params.push(productId, cafeteria_id);
        const result = await pool.query(
            `UPDATE products SET ${sets.join(', ')}
             WHERE id = $${params.length - 1} AND cafeteria_id = $${params.length}
             RETURNING id, cafeteria_id, name, price, description, is_available, category_id,
                       (image_data IS NOT NULL) AS has_image`,
            params
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Product not found' });
        }

        const { has_image, ...product } = result.rows[0];
        product.image_url = has_image ? productImageUrl(req, product.id) : null;
        res.status(200).json({ status: 'success', message: 'Product updated', product });

    } catch (err) {
        console.error('Error updating product:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating product' });
    }
});

// ==========================================
// מחיקת מוצר - מנהל מחובר בלבד, ורק מוצר של הקפיטריה שלו
// DELETE /api/products/:id
// מוצר שכבר הוזמן לא נמחק (כדי לא לפגוע בהיסטוריית ההזמנות) - במקרה כזה מסמנים אותו "לא זמין".
// ==========================================
app.delete('/api/products/:id', requireCafeteria, async (req, res) => {
    const productId = Number(req.params.id);
    if (!Number.isInteger(productId) || productId < 1) {
        return res.status(400).json({ status: 'error', message: 'Invalid product id' });
    }
    try {
        const own = await pool.query(
            'SELECT 1 FROM products WHERE id = $1 AND cafeteria_id = $2',
            [productId, req.cafeteria.cafeteriaId]
        );
        if (own.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Product not found' });
        }

        const used = await pool.query('SELECT 1 FROM order_items WHERE product_id = $1 LIMIT 1', [productId]);
        if (used.rows.length > 0) {
            return res.status(409).json({
                status: 'error',
                message: 'Product has past orders and cannot be deleted',
                code: 'PRODUCT_HAS_ORDERS'
            });
        }

        await pool.query('DELETE FROM products WHERE id = $1 AND cafeteria_id = $2', [productId, req.cafeteria.cafeteriaId]);
        res.status(200).json({ status: 'success', message: 'Product deleted' });

    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).json({ status: 'error', message: 'Server error while deleting product' });
    }
});

// ==========================================
// 4. שליפת כל המוצרים של קפיטריה מסוימת - ציבורי (התפריט)
// ==========================================
app.get('/api/products', async (req, res) => {
    const cafeteriaName = cleanText(req.query.cafeteriaName, 100);

    if (!cafeteriaName) {
        return res.status(400).json({
            status: 'error',
            message: 'cafeteriaName query parameter is required'
        });
    }

    try {
        const cafeteriaResult = await pool.query(
            'SELECT id FROM cafeterias WHERE name = $1',
            [cafeteriaName]
        );

        if (cafeteriaResult.rows.length === 0) {
            return res.status(404).json({
                status: 'error',
                message: 'Cafeteria not found'
            });
        }

        const cafeteria_id = cafeteriaResult.rows[0].id;

        const productsResult = await pool.query(
            `SELECT
                p.id,
                p.name,
                p.price,
                p.description,
                p.is_available,
                (p.image_data IS NOT NULL) AS has_image,
                c.name AS category_name
             FROM products p
             LEFT JOIN categories c ON p.category_id = c.id
             WHERE p.cafeteria_id = $1
             ORDER BY p.id DESC`,
            [cafeteria_id]
        );

        // לכל מוצר עם תמונה - כתובת מלאה לתמונה שבמסד
        const products = productsResult.rows.map(({ has_image, ...p }) => ({
            ...p,
            image_url: has_image ? productImageUrl(req, p.id) : null
        }));

        res.status(200).json({
            status: 'success',
            count: products.length,
            products
        });

    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while fetching products'
        });
    }
});

// ==========================================
// ארנק והזמנות
// ==========================================
// היתרה של תלמיד נשמרת בעמודה balance בטבלת students.
// כל שינוי ביתרה מעדכן את העמודה הזאת, ובנוסף נרשם ב-balance_transactions לצורך מעקב.
async function getStudentBalance(db, studentId) {
    const result = await db.query(
        'SELECT COALESCE(balance, 0) AS balance FROM students WHERE id = $1',
        [studentId]
    );
    return result.rows.length ? Number(result.rows[0].balance) : 0;
}

// ==========================================
// 5. יתרת הארנק של התלמיד המחובר
// ==========================================
app.get('/api/students/balance', requireStudent, async (req, res) => {
    try {
        const balance = await getStudentBalance(pool, req.student.studentId);
        res.status(200).json({ status: 'success', balance });
    } catch (err) {
        console.error('Error fetching balance:', err);
        res.status(500).json({ status: 'error', message: 'Server error while fetching balance' });
    }
});

// ==========================================
// 6. ביצוע הזמנה על ידי תלמיד מחובר
// גוף הבקשה:
// {
//   "items": [ { "productId": 3, "quantity": 2, "notes": "בלי בצל" } ],
//   "notes": "הערה כללית להזמנה"
// }
// ==========================================
const MAX_ITEMS_PER_ORDER = 30;
const MAX_QUANTITY_PER_ITEM = 20;

app.post('/api/orders', requireStudent, async (req, res) => {
    const { items } = req.body;
    const notes = cleanText(req.body.notes, 300);
    const studentId = req.student.studentId;
    const cafeteriaId = req.student.cafeteriaId;

    // אמצעי תשלום: wallet = מהיתרה באפליקציה, cash = מזומן באיסוף
    const paymentMethod = req.body.paymentMethod === undefined ? 'wallet' : req.body.paymentMethod;
    if (paymentMethod !== 'wallet' && paymentMethod !== 'cash') {
        return res.status(400).json({ status: 'error', message: "paymentMethod must be 'wallet' or 'cash'" });
    }

    if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({
            status: 'error',
            message: 'Order must contain at least one item'
        });
    }

    if (items.length > MAX_ITEMS_PER_ORDER) {
        return res.status(400).json({
            status: 'error',
            message: `An order can contain up to ${MAX_ITEMS_PER_ORDER} items`
        });
    }

    for (const item of items) {
        const productId = Number(item && item.productId);
        const qty = Number(item && item.quantity);
        if (!Number.isInteger(productId) || productId < 1 ||
            !Number.isInteger(qty) || qty < 1 || qty > MAX_QUANTITY_PER_ITEM) {
            return res.status(400).json({
                status: 'error',
                message: `Each item needs a valid productId and quantity between 1 and ${MAX_QUANTITY_PER_ITEM}`
            });
        }
    }

    // כל ההזמנה רצה בתוך טרנזקציה אחת: או שהכול נשמר, או ששום דבר לא נשמר
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // קפיטריה נעולה - לא מקבלים הזמנות
        const openCheck = await client.query(
            'SELECT COALESCE(is_open, FALSE) AS is_open, COALESCE(auto_schedule, FALSE) AS auto_schedule, schedule FROM cafeterias WHERE id = $1',
            [cafeteriaId]
        );
        if (openCheck.rows.length === 0 || !isCafeteriaOpenNow(openCheck.rows[0])) {
            await client.query('ROLLBACK');
            return res.status(403).json({
                status: 'error',
                message: 'Cafeteria is closed',
                code: 'CAFETERIA_CLOSED'
            });
        }

        // נעילת שורת התלמיד וקריאת היתרה - מונעת מצב שבו שתי הזמנות במקביל
        // עוברות את בדיקת היתרה ומורידות יותר כסף ממה שיש
        const studentLock = await client.query(
            'SELECT COALESCE(balance, 0) AS balance FROM students WHERE id = $1 FOR UPDATE',
            [studentId]
        );

        if (studentLock.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ status: 'error', message: 'Student not found' });
        }

        const balance = Number(studentLock.rows[0].balance);

        // שליפת המוצרים מהמסד - המחיר נלקח מהשרת ולא מהלקוח
        const productIds = [...new Set(items.map(i => Number(i.productId)))];
        const productsResult = await client.query(
            `SELECT id, name, price, is_available
             FROM products
             WHERE id = ANY($1::int[]) AND cafeteria_id = $2`,
            [productIds, cafeteriaId]
        );

        const productsById = {};
        for (const p of productsResult.rows) {
            productsById[p.id] = p;
        }

        let totalPrice = 0;
        for (const item of items) {
            const product = productsById[Number(item.productId)];

            if (!product) {
                await client.query('ROLLBACK');
                return res.status(404).json({
                    status: 'error',
                    message: `Product ${item.productId} not found in your cafeteria`
                });
            }

            if (!product.is_available) {
                await client.query('ROLLBACK');
                return res.status(400).json({
                    status: 'error',
                    message: `Product '${product.name}' is not available right now`
                });
            }

            totalPrice += Number(product.price) * Number(item.quantity);
        }

        // עיגול לאגורות
        totalPrice = Math.round(totalPrice * 100) / 100;

        // בדיקת יתרה
        if (paymentMethod === 'wallet' && balance < totalPrice) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                status: 'error',
                message: 'Insufficient balance',
                balance,
                totalPrice
            });
        }

        // יצירת ההזמנה
        const orderResult = await client.query(
            `INSERT INTO orders (cafeteria_id, student_id, status, total_price, notes, payment_method)
             VALUES ($1, $2, 'pending', $3, $4, $5)
             RETURNING *`,
            [cafeteriaId, studentId, totalPrice, notes, paymentMethod]
        );
        const order = orderResult.rows[0];

        // שמירת פריטי ההזמנה
        const orderItems = [];
        for (const item of items) {
            const product = productsById[Number(item.productId)];
            const itemResult = await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, unit_price, item_notes)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING *`,
                [order.id, product.id, Number(item.quantity), product.price, cleanText(item.notes, 200)]
            );
            orderItems.push({ ...itemResult.rows[0], product_name: product.name });
        }

        // הורדת הסכום מהארנק - רק בתשלום מהיתרה. במזומן לא נוגעים בארנק
        let newBalance = balance;
        if (paymentMethod === 'wallet') {
            const balanceUpdate = await client.query(
                'UPDATE students SET balance = COALESCE(balance, 0) - $1 WHERE id = $2 RETURNING balance',
                [totalPrice, studentId]
            );
            newBalance = Number(balanceUpdate.rows[0].balance);

            // רישום התנועה לצורך מעקב
            await client.query(
                `INSERT INTO balance_transactions (student_id, amount, type, description)
                 VALUES ($1, $2, 'purchase', $3)`,
                [studentId, -totalPrice, `הזמנה מספר ${order.id}`]
            );
        }

        await client.query('COMMIT');

        res.status(201).json({
            status: 'success',
            message: 'Order placed successfully!',
            order: { ...order, items: orderItems },
            newBalance
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error placing order:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while placing order'
        });
    } finally {
        client.release();
    }
});

// ==========================================
// 7. שליפת כל ההזמנות של הקפיטריה - מנהל מחובר בלבד
// GET /api/orders
// הקפיטריה נקבעת לפי ה-token של המנהל, כך שמנהל רואה רק את ההזמנות שלו
// ==========================================
app.get('/api/orders', requireCafeteria, async (req, res) => {
    const cafeteria_id = req.cafeteria.cafeteriaId;

    try {
        // כל הזמנה כוללת את פרטי התלמיד ואת רשימת הפריטים שלה
        const ordersResult = await pool.query(
            `SELECT
                o.id,
                o.status,
                o.total_price,
                o.notes,
                o.payment_method,
                o.picked_up_at,
                o.created_at,
                s.id   AS student_id,
                s.name AS student_name,
                s.phone AS student_phone,
                COALESCE(
                    json_agg(
                        json_build_object(
                            'id', oi.id,
                            'product_id', oi.product_id,
                            'product_name', p.name,
                            'quantity', oi.quantity,
                            'unit_price', oi.unit_price,
                            'item_notes', oi.item_notes
                        ) ORDER BY oi.id
                    ) FILTER (WHERE oi.id IS NOT NULL),
                    '[]'
                ) AS items
             FROM orders o
             JOIN students s ON s.id = o.student_id
             LEFT JOIN order_items oi ON oi.order_id = o.id
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE o.cafeteria_id = $1
             GROUP BY o.id, s.id
             ORDER BY o.created_at DESC`,
            [cafeteria_id]
        );

        res.status(200).json({
            status: 'success',
            count: ordersResult.rows.length,
            orders: ordersResult.rows
        });

    } catch (err) {
        console.error('Error fetching orders:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while fetching orders'
        });
    }
});

// ==========================================
// 8. עדכון סטטוס הזמנה (מוכן / בוטל) - מנהל מחובר בלבד
// PUT /api/orders/:id/status
// גוף הבקשה: { "status": "ready" } או { "status": "cancelled" }
// רק הזמנה שעדיין ממתינה (pending) ושייכת לקפיטריה של המנהל אפשר לעדכן.
// בביטול - הסכום חוזר לארנק של התלמיד.
// ==========================================
const ALLOWED_STATUS_UPDATES = ['ready', 'cancelled'];

app.put('/api/orders/:id/status', requireCafeteria, async (req, res) => {
    const orderId = Number(req.params.id);
    const { status } = req.body;
    const cafeteria_id = req.cafeteria.cafeteriaId;

    if (!Number.isInteger(orderId) || orderId < 1) {
        return res.status(400).json({ status: 'error', message: 'Invalid order id' });
    }

    if (!ALLOWED_STATUS_UPDATES.includes(status)) {
        return res.status(400).json({
            status: 'error',
            message: `Status must be one of: ${ALLOWED_STATUS_UPDATES.join(', ')}`
        });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // נעילת ההזמנה - מונעת החזר כספי כפול אם לוחצים "בטל" פעמיים
        // ומוודאת שההזמנה שייכת לקפיטריה של המנהל המחובר
        const orderResult = await client.query(
            'SELECT * FROM orders WHERE id = $1 AND cafeteria_id = $2 FOR UPDATE',
            [orderId, cafeteria_id]
        );

        if (orderResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ status: 'error', message: `Order ${orderId} not found` });
        }

        const order = orderResult.rows[0];

        if (order.status !== 'pending') {
            await client.query('ROLLBACK');
            return res.status(400).json({
                status: 'error',
                message: `Order is already '${order.status}' and cannot be changed`
            });
        }

        const updateResult = await client.query(
            'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
            [status, orderId]
        );

        // בביטול - החזרת הכסף לארנק
        let refunded = 0;
        // החזר לארנק רק אם שולם מהארנק (הזמנה במזומן לא שולמה מראש)
        if (status === 'cancelled' && order.payment_method !== 'cash') {
            refunded = Number(order.total_price);

            // עדכון היתרה בטבלת students
            await client.query(
                'UPDATE students SET balance = COALESCE(balance, 0) + $1 WHERE id = $2',
                [refunded, order.student_id]
            );

            // רישום התנועה לצורך מעקב
            await client.query(
                `INSERT INTO balance_transactions (student_id, amount, type, description)
                 VALUES ($1, $2, 'refund', $3)`,
                [order.student_id, refunded, `החזר על ביטול הזמנה מספר ${order.id}`]
            );
        }

        await client.query('COMMIT');

        res.status(200).json({
            status: 'success',
            message: status === 'cancelled'
                ? 'Order cancelled and refunded'
                : 'Order marked as ready',
            order: updateResult.rows[0],
            refunded
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Error updating order status:', err);
        res.status(500).json({
            status: 'error',
            message: 'Server error while updating order status'
        });
    } finally {
        client.release();
    }
});

// ==========================================
// סימון הזמנה כנאספה - מנהל קפיטריה מחובר בלבד
// PUT /api/orders/:id/pickup
// אפשר רק להזמנה במצב "מוכנה" שעוד לא נאספה. נשמרים התאריך והשעה של האיסוף.
// דורש עמודה: ALTER TABLE orders ADD COLUMN IF NOT EXISTS picked_up_at TIMESTAMPTZ;
// ==========================================
app.put('/api/orders/:id/pickup', requireCafeteria, async (req, res) => {
    const orderId = Number(req.params.id);
    if (!Number.isInteger(orderId) || orderId < 1) {
        return res.status(400).json({ status: 'error', message: 'Invalid order id' });
    }
    try {
        const result = await pool.query(
            `UPDATE orders SET picked_up_at = NOW()
             WHERE id = $1 AND cafeteria_id = $2 AND status = 'ready' AND picked_up_at IS NULL
             RETURNING id, picked_up_at`,
            [orderId, req.cafeteria.cafeteriaId]
        );
        if (result.rows.length > 0) {
            return res.status(200).json({ status: 'success', order: result.rows[0] });
        }
        const check = await pool.query(
            'SELECT status, picked_up_at FROM orders WHERE id = $1 AND cafeteria_id = $2',
            [orderId, req.cafeteria.cafeteriaId]
        );
        if (check.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: `Order ${orderId} not found` });
        }
        if (check.rows[0].picked_up_at) {
            return res.status(400).json({ status: 'error', message: 'Order was already picked up', picked_up_at: check.rows[0].picked_up_at });
        }
        return res.status(400).json({ status: 'error', message: 'Only a ready order can be marked as picked up' });
    } catch (err) {
        console.error('Error marking order as picked up:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating order' });
    }
});

// ==========================================
// הזמנות של התלמיד המחובר - הוסף ל-server.js לפני "נתיב שלא קיים"
// GET /api/students/orders
// התלמיד נקבע לפי ה-token, כך שאי אפשר לראות הזמנות של אחרים
// ==========================================
app.get('/api/students/orders', requireStudent, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                o.id,
                o.status,
                o.total_price,
                o.notes,
                o.payment_method,
                o.picked_up_at,
                o.created_at,
                COALESCE(
                    json_agg(
                        json_build_object(
                            'product_name', p.name,
                            'quantity', oi.quantity,
                            'item_notes', oi.item_notes
                        ) ORDER BY oi.id
                    ) FILTER (WHERE oi.id IS NOT NULL),
                    '[]'
                ) AS items
             FROM orders o
             LEFT JOIN order_items oi ON oi.order_id = o.id
             LEFT JOIN products p ON p.id = oi.product_id
             WHERE o.student_id = $1
             GROUP BY o.id
             ORDER BY o.created_at DESC
             LIMIT 100`,
            [req.student.studentId]
        );

        res.status(200).json({ status: 'success', count: result.rows.length, orders: result.rows });

    } catch (err) {
        console.error('Error fetching student orders:', err);
        res.status(500).json({ status: 'error', message: 'Server error while fetching orders' });
    }
});

// ==========================================
// פתיחה / נעילה של הקפיטריה
// דורש עמודה: ALTER TABLE cafeterias ADD COLUMN IF NOT EXISTS is_open BOOLEAN NOT NULL DEFAULT FALSE;  -- ברירת מחדל: סגורה
// GET /api/cafeteria-status - תלמיד או צוות מחוברים, מחזיר את מצב הקפיטריה שלהם
// PUT /api/cafeteria-status - צוות בלבד, גוף הבקשה: { "is_open": true | false }
// ==========================================
app.get('/api/cafeteria-status', async (req, res) => {
    const payload = readToken(req);
    if (!payload || (payload.role !== 'student' && payload.role !== 'cafeteria')) {
        return res.status(401).json({ status: 'error', message: 'Please log in again' });
    }

    try {
        const result = await pool.query(
            'SELECT COALESCE(is_open, FALSE) AS is_open, COALESCE(auto_schedule, FALSE) AS auto_schedule, schedule FROM cafeterias WHERE id = $1',
            [payload.cafeteriaId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Cafeteria not found' });
        }
        const row = result.rows[0];
        res.status(200).json({
            status: 'success',
            is_open: isCafeteriaOpenNow(row),
            auto_schedule: row.auto_schedule,
            manual_open: row.is_open,
            schedule: payload.role === 'cafeteria' ? row.schedule : undefined
        });
    } catch (err) {
        console.error('Error fetching cafeteria status:', err);
        res.status(500).json({ status: 'error', message: 'Server error while fetching status' });
    }
});

app.put('/api/cafeteria-status', requireCafeteria, async (req, res) => {
    const { is_open } = req.body;
    if (typeof is_open !== 'boolean') {
        return res.status(400).json({ status: 'error', message: 'is_open must be true or false' });
    }

    try {
        const result = await pool.query(
            'UPDATE cafeterias SET is_open = $1 WHERE id = $2 RETURNING is_open',
            [is_open, req.cafeteria.cafeteriaId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Cafeteria not found' });
        }
        res.status(200).json({ status: 'success', is_open: result.rows[0].is_open });
    } catch (err) {
        console.error('Error updating cafeteria status:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating status' });
    }
});

// הגדרת שעות פתיחה אוטומטיות - צוות בלבד
// PUT /api/cafeteria-schedule  { auto_schedule: true|false, schedule: { "0": {enabled, open, close}, ... "6": {...} } }
// דורש עמודות: ALTER TABLE cafeterias ADD COLUMN IF NOT EXISTS auto_schedule BOOLEAN NOT NULL DEFAULT FALSE, ADD COLUMN IF NOT EXISTS schedule JSONB;
app.put('/api/cafeteria-schedule', requireCafeteria, async (req, res) => {
    if (typeof req.body.auto_schedule !== 'boolean') {
        return res.status(400).json({ status: 'error', message: 'auto_schedule must be true or false' });
    }
    const schedule = validateSchedule(req.body.schedule);
    if (!schedule) {
        return res.status(400).json({ status: 'error', message: 'Invalid schedule: each enabled day needs opening time earlier than closing time (HH:MM)' });
    }
    try {
        const result = await pool.query(
            `UPDATE cafeterias SET auto_schedule = $1, schedule = $2::jsonb WHERE id = $3
             RETURNING COALESCE(is_open, FALSE) AS is_open, auto_schedule, schedule`,
            [req.body.auto_schedule, JSON.stringify(schedule), req.cafeteria.cafeteriaId]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ status: 'error', message: 'Cafeteria not found' });
        }
        const row = result.rows[0];
        res.status(200).json({ status: 'success', is_open: isCafeteriaOpenNow(row), auto_schedule: row.auto_schedule, schedule: row.schedule });
    } catch (err) {
        console.error('Error updating cafeteria schedule:', err);
        res.status(500).json({ status: 'error', message: 'Server error while updating schedule' });
    }
});

// ==========================================
// נתיב שלא קיים
// ==========================================
app.use((req, res) => {
    res.status(404).json({ status: 'error', message: 'Not found' });
});

// ==========================================
// טיפול כללי בשגיאות - לא חושף פרטים פנימיים ללקוח
// ==========================================
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        const message = err.code === 'LIMIT_FILE_SIZE'
            ? 'Image is too large (max 5MB)'
            : 'Only JPG, PNG or WEBP images are allowed';
        return res.status(400).json({ status: 'error', message });
    }

    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({ status: 'error', message: 'Origin not allowed' });
    }

    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({ status: 'error', message: 'Invalid JSON' });
    }

    if (err.type === 'entity.too.large') {
        return res.status(413).json({ status: 'error', message: 'Request is too large' });
    }

    console.error('Unhandled error:', err);
    res.status(500).json({ status: 'error', message: 'Server error' });
});

// הפעלת השרת
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT} (${IS_PRODUCTION ? 'production' : 'development'})`);
});
