// ==========================================
// שליחת SMS
// ==========================================
// אם הוגדרו פרטי Twilio בקובץ .env - ההודעה נשלחת באמת.
// אחרת (בפיתוח מקומי) - הקוד פשוט מודפס לטרמינל, כדי שתוכל לבדוק בלי לשלם על SMS.

let twilioClient = null;

if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER) {
    const twilio = require('twilio');
    twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
}

// המרת מספר ישראלי (0501234567) לפורמט בינלאומי (+972501234567) שספקי SMS דורשים
function toInternational(phone) {
    if (phone.startsWith('0')) {
        return '+972' + phone.slice(1);
    }
    return phone.startsWith('+') ? phone : '+' + phone;
}

async function sendSms(phone, message) {
    if (!twilioClient) {
        console.log(`[DEV SMS] to ${phone}: ${message}`);
        return;
    }

    await twilioClient.messages.create({
        body: message,
        from: process.env.TWILIO_FROM_NUMBER,
        to: toInternational(phone)
    });
}

module.exports = { sendSms };
