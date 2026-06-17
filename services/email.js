// Wrapper sobre Resend usando la API REST con fetch nativo de Node 18+.
// No agrega dependencia npm: usa solo `process.env.RESEND_API_KEY`.
// Documentación: https://resend.com/docs/api-reference/emails/send-email

const RESEND_URL = 'https://api.resend.com/emails';
const FROM_DEFAULT = 'Eva <onboarding@resend.dev>';

async function sendEmail({ to, subject, html, from }) {
    const apiKey = process.env.RESEND_API_KEY;
    if (!apiKey) {
        console.error('[email] RESEND_API_KEY no está configurada');
        throw new Error('Servicio de email no configurado');
    }

    const res = await fetch(RESEND_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
            from: from || FROM_DEFAULT,
            to: Array.isArray(to) ? to : [to],
            subject,
            html,
        }),
    });

    if (!res.ok) {
        const text = await res.text().catch(() => '');
        console.error('[email] Resend respondió', res.status, text);
        throw new Error(`Resend error ${res.status}`);
    }
    return res.json();
}

function buildVerificationHtml(code, nombre) {
    const saludo = nombre ? `Hola ${escapeHtml(nombre)},` : 'Hola,';
    return `
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F5F7F5;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#F5F7F5;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" style="max-width:520px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,0.06);">
        <tr><td style="background:#1B5E20;padding:28px 32px;">
          <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:800;letter-spacing:-0.3px;">Eva Finanzas</h1>
          <p style="margin:6px 0 0;color:#C8E6C9;font-size:13px;">Verificación de correo</p>
        </td></tr>
        <tr><td style="padding:32px;color:#1a1a1a;">
          <p style="margin:0 0 16px;font-size:15px;">${saludo}</p>
          <p style="margin:0 0 24px;font-size:15px;line-height:1.55;">
            Usa el siguiente código para verificar tu correo en Eva. El código expira en
            <strong>10 minutos</strong>.
          </p>
          <div style="text-align:center;margin:28px 0;">
            <div style="display:inline-block;background:#E8F5E9;border:2px solid #1B5E20;border-radius:14px;padding:18px 28px;">
              <span style="font-family:'Courier New',monospace;font-size:34px;font-weight:800;letter-spacing:8px;color:#1B5E20;">${code}</span>
            </div>
          </div>
          <p style="margin:24px 0 0;font-size:13px;color:#757575;line-height:1.5;">
            Si no solicitaste este código, ignora este correo. Nadie podrá acceder a tu cuenta sin él.
          </p>
        </td></tr>
        <tr><td style="background:#FAFAFA;padding:18px 32px;border-top:1px solid #EEEEEE;">
          <p style="margin:0;font-size:12px;color:#9e9e9e;text-align:center;">
            Este correo fue enviado por Eva Finanzas. No respondas a esta dirección.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`.trim();
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
}

async function sendVerificationCode(to, code, nombre) {
    return sendEmail({
        to,
        subject: `Tu código de verificación Eva: ${code}`,
        html: buildVerificationHtml(code, nombre),
    });
}

module.exports = { sendEmail, sendVerificationCode };
