/*
  send_otp.js
  Usage: node backend/utils/send_otp.js <toEmail> <otp>

  Requires env vars:
    - GMAIL_USER
    - GMAIL_APP_PASSWORD
*/

const nodemailer = require('nodemailer');

function fail(msg) {
  process.stderr.write(String(msg || 'Failed') + '\n');
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length < 2) {
  fail('Usage: node backend/utils/send_otp.js <toEmail> <otp>');
}

const toEmail = String(args[0] || '').trim();
const otp = String(args[1] || '').trim();

if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(toEmail)) {
  fail('Invalid toEmail');
}
if (!/^\d{6}$/.test(otp)) {
  fail('Invalid otp (must be 6 digits)');
}

const user = String(process.env.GMAIL_USER || '').trim();
const pass = String(process.env.GMAIL_APP_PASSWORD || '').trim().replace(/\s+/g, '');

if (!user || !pass) {
  fail('Missing env vars: GMAIL_USER and/or GMAIL_APP_PASSWORD');
}

async function main() {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  });

  const escapeHtml = (value) =>
    String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

  const buildHtml = ({ otpValue }) => {
    const safeOtp = escapeHtml(otpValue);
    const preheader = `Your SecureScan password reset code is ${safeOtp}. It expires in 10 minutes.`;

    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta name="color-scheme" content="light only" />
    <title>SecureScan OTP</title>
  </head>
  <body style="margin:0;padding:0;background-color:#f5f7fb;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">
      ${preheader}
    </div>

    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f5f7fb;">
      <tr>
        <td align="center" style="padding:28px 16px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:600px;max-width:100%;">
            <tr>
              <td style="padding:0 0 14px 0;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:18px;font-weight:700;letter-spacing:0.2px;color:#0f172a;">
                  SecureScan
                </div>
              </td>
            </tr>

            <tr>
              <td style="background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:22px;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:24px;color:#111827;">
                  <div style="font-size:20px;line-height:28px;font-weight:700;margin:0 0 10px 0;color:#0f172a;">
                    Password reset request
                  </div>
                  <div style="margin:0 0 14px 0;">
                    Use the following one-time password (OTP) to reset your SecureScan account password:
                  </div>

                  <div style="margin:18px 0 18px 0;text-align:center;">
                    <div style="display:inline-block;background:#388bfd;border:1px solid #388bfd;border-radius:10px;padding:14px 18px;">
                      <div style="font-family:Consolas,Monaco,'Courier New',monospace;font-size:28px;letter-spacing:6px;font-weight:700;color:#ffffff;">
                        ${safeOtp}
                      </div>
                    </div>
                  </div>

                  <div style="margin:0 0 6px 0;color:#374151;">
                    This code expires in <b>10 minutes</b>.
                  </div>
                  <div style="margin:0;color:#374151;">
                    If you did not request a password reset, you can safely ignore this email.
                  </div>
                </div>
              </td>
            </tr>

            <tr>
              <td style="padding:14px 4px 0 4px;">
                <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:18px;color:#6b7280;">
                  This message was sent automatically by SecureScan.
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
  };

  const subject = 'SecureScan Password Reset OTP';
  const text = `Your SecureScan password reset OTP is: ${otp}\n\nThis code expires in 10 minutes. If you did not request this, you can ignore this email.`;
  const html = buildHtml({ otpValue: otp });

  await transporter.sendMail({
    from: { name: 'SecureScan', address: user },
    to: toEmail,
    subject,
    text,
    html,
  });

  process.stdout.write('sent\n');
}

main().catch((err) => {
  fail(err && err.message ? err.message : String(err));
});
