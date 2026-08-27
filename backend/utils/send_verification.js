/*
  send_verification.js
  Usage: node backend/utils/send_verification.js <toEmail> <verifyUrl>

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
  fail('Usage: node backend/utils/send_verification.js <toEmail> <verifyUrl>');
}

const toEmail = String(args[0] || '').trim();
const verifyUrl = String(args[1] || '').trim();

if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(toEmail)) {
  fail('Invalid toEmail');
}
if (!/^https?:\/\//i.test(verifyUrl) || verifyUrl.length < 12) {
  fail('Invalid verifyUrl');
}

const user = String(process.env.GMAIL_USER || '').trim();
const pass = String(process.env.GMAIL_APP_PASSWORD || '').trim().replace(/\s+/g, '');

if (!user || !pass) {
  fail('Missing env vars: GMAIL_USER and/or GMAIL_APP_PASSWORD');
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildHtml({ url }) {
  const safeUrl = escapeHtml(url);
  const preheader = 'Verify your SecureScan email to activate your account.';

  // Email-friendly inline CSS. Theme uses SecureScan "info" blue (#388bfd).
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <meta name="color-scheme" content="light only" />
    <title>Verify your email</title>
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
                    Verify your email
                  </div>
                  <div style="margin:0 0 16px 0;">
                    Click the button below to verify your email address and activate your SecureScan account.
                  </div>

                  <div style="margin:18px 0 18px 0;text-align:center;">
                    <a href="${safeUrl}" style="display:inline-block;background:#388bfd;color:#ffffff;text-decoration:none;border-radius:10px;padding:12px 18px;font-family:Arial,Helvetica,sans-serif;font-size:14px;font-weight:700;">
                      Verify Email
                    </a>
                  </div>

                  <div style="margin:0 0 6px 0;color:#374151;">
                    If the button doesn’t work, copy and paste this link into your browser:
                  </div>
                  <div style="margin:0;color:#111827;word-break:break-all;">
                    <a href="${safeUrl}" style="color:#388bfd;text-decoration:underline;">${safeUrl}</a>
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
}

async function main() {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass },
  });

  const subject = 'Verify your SecureScan email';
  const text = `Verify your SecureScan email to activate your account:\n\n${verifyUrl}\n\nIf you did not create an account, you can ignore this email.`;
  const html = buildHtml({ url: verifyUrl });

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
