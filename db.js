// חיבור למסד הנתונים PostgreSQL
// כל פרטי החיבור מגיעים ממשתנה אחד: DATABASE_URL
//   מקומית:   בקובץ .env  ->  DATABASE_URL=postgresql://postgres:הסיסמה@localhost:5432/שם_המסד
//   ב-Railway: במשתני השירות ->  DATABASE_URL=${{Postgres.DATABASE_URL}}
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL is missing - server will not start');
    process.exit(1);
}

// SSL נדרש רק כשמתחברים למסד דרך האינטרנט (כתובת ציבורית).
// בתוך Railway (הרשת הפנימית) ובמחשב המקומי לא צריך - משאירים DB_SSL ריק
const useSsl = process.env.DB_SSL === 'true';

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: useSsl ? { rejectUnauthorized: false } : false,
    max: 10,                        // מקסימום חיבורים פתוחים במקביל
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

// חיבור שנפל באמצע (למשל המסד הופעל מחדש) - רושמים בלוג ולא מפילים את השרת
pool.on('error', (err) => {
    console.error('Unexpected database error:', err.message);
});

module.exports = pool;
