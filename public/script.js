// Client-side validation + login request.
// NOTE: client-side validation is a UX convenience only — it can be bypassed
// with the devtools/curl/Burp, which is exactly why the server re-validates.

const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const emailError = document.getElementById('email-error');
const passwordError = document.getElementById('password-error');
const resultBox = document.getElementById('result');
const loginBtn = document.getElementById('login-btn');

// Show which mode the server is running in.
fetch('/api/mode')
  .then((r) => r.json())
  .then((d) => {
    const banner = document.getElementById('mode-banner');
    banner.hidden = false;
    if (d.vulnerable) {
      banner.className = 'banner vuln';
      banner.textContent = '⚠ VULNERABLE mode — SQL injection & XSS are possible here.';
    } else {
      banner.className = 'banner secure';
      banner.textContent = '✓ SECURE mode — parameterized queries, bcrypt, output encoding.';
    }
  })
  .catch(() => {});

// Returns true if the form passes client-side checks.
function validateClient() {
  let valid = true;
  emailError.textContent = '';
  passwordError.textContent = '';

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (!email) {
    emailError.textContent = 'Email is required.';
    valid = false;
  } else if (!email.includes('@')) {
    emailError.textContent = 'Email must contain "@".';
    valid = false;
  }

  if (!password) {
    passwordError.textContent = 'Password is required.';
    valid = false;
  } else if (password.length < 8) {
    passwordError.textContent = 'Password must be at least 8 characters.';
    valid = false;
  }

  return valid;
}

async function submitLogin() {
  resultBox.textContent = '';
  resultBox.className = 'result';

  if (!validateClient()) return;

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: emailInput.value.trim(),
        password: passwordInput.value,
      }),
    });
    const data = await res.json();

    resultBox.className = 'result ' + (data.ok ? 'ok' : 'bad');
    // The server's message is rendered as HTML. In SECURE mode the server has
    // already escaped it; in VULNERABLE mode it is raw -> reflected XSS fires.
    resultBox.innerHTML = data.message;
  } catch (err) {
    resultBox.className = 'result bad';
    resultBox.textContent = 'Could not reach the server.';
  }
}

loginBtn.addEventListener('click', submitLogin);
passwordInput.addEventListener('keyup', (e) => {
  if (e.key === 'Enter') submitLogin();
});
