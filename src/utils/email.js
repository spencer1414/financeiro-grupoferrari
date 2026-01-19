const nodemailer = require('nodemailer');

function canSendEmail() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

function createTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

async function sendInviteEmail({ to, subject, html }) {
  if (!canSendEmail()) {
    // Fallback: log to console
    console.log('--- EMAIL SIMULADO (configure SMTP no .env) ---');
    console.log('Para:', to);
    console.log('Assunto:', subject);
    console.log(html.replace(/<[^>]+>/g, ' '));
    console.log('---------------------------------------------');
    return { simulated: true };
  }
  const transporter = createTransport();
  return transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject,
    html
  });
}

module.exports = { sendInviteEmail, canSendEmail };
