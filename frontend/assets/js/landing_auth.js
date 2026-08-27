/* SecureScan landing auth sheet (Sign In / Sign Up) */

(function () {
  const $ = (sel) => document.querySelector(sel);

  const sheet = $('#authSheet');
  const backdrop = $('#authBackdrop');
  const closeBtn = $('#authClose');
  const tabSignIn = $('#tabSignIn');
  const tabSignUp = $('#tabSignUp');
  const title = $('#authTitle');

  const formSignIn = $('#signInForm');
  const formSignUp = $('#signUpForm');

  const errSignIn = $('#signInError');
  const errSignUp = $('#signUpError');

  const openBtns = document.querySelectorAll('[data-auth-open]');

  function setText(el, text) {
    if (!el) return;
    el.textContent = String(text ?? '');
  }

  function show(el) {
    if (!el) return;
    el.style.display = 'block';
  }

  function hide(el) {
    if (!el) return;
    el.style.display = 'none';
  }

  function openSheet(mode) {
    if (!sheet || !backdrop) return;

    sheet.classList.add('is-open');
    backdrop.classList.add('is-open');
    document.documentElement.classList.add('no-scroll');

    selectMode(mode || 'signin');

    // focus first input
    const first = sheet.querySelector('input');
    if (first) first.focus();
  }

  function closeSheet() {
    if (!sheet || !backdrop) return;

    sheet.classList.remove('is-open');
    backdrop.classList.remove('is-open');
    document.documentElement.classList.remove('no-scroll');

    // clear errors
    hide(errSignIn);
    hide(errSignUp);
    setText(errSignIn, '');
    setText(errSignUp, '');
  }

  function selectMode(mode) {
    const m = mode === 'signup' ? 'signup' : 'signin';

    tabSignIn?.classList.toggle('active', m === 'signin');
    tabSignUp?.classList.toggle('active', m === 'signup');

    if (m === 'signin') {
      setText(title, 'Sign in');
      show(formSignIn);
      hide(formSignUp);
    } else {
      setText(title, 'Create account');
      show(formSignUp);
      hide(formSignIn);
    }
  }

  function saveAuth(auth) {
    if (!auth) return;
    if (auth.token) localStorage.setItem('ss_token', auth.token);
    if (auth.username) localStorage.setItem('ss_user', auth.username);
    if (auth.email) localStorage.setItem('ss_email', auth.email);
    if (auth.role) localStorage.setItem('ss_role', auth.role);
  }

  async function apiJson(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });

    let data = null;
    try {
      data = await res.json();
    } catch (_) {
      // non-json
    }

    if (!res.ok) {
      const msg = data?.error || data?.message || `Request failed (${res.status})`;
      throw new Error(msg);
    }

    return data;
  }

  async function handleSignIn(e) {
    e.preventDefault();
    hide(errSignIn);
    setText(errSignIn, '');

    const username = $('#signInUsername')?.value?.trim() || '';
    const password = $('#signInPassword')?.value || '';

    if (!username || !password) {
      setText(errSignIn, 'Please enter your username and password.');
      show(errSignIn);
      return;
    }

    const btn = $('#signInBtn');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
    }

    try {
      const data = await apiJson('/api/auth/login', { username, password });
      if (!data?.success) throw new Error(data?.error || 'Login failed');

      saveAuth({
        token: data.token,
        username: data.username || username,
        email: data.email,
        role: data.role || 'user',
      });

      window.location.href = '/dashboard';
    } catch (err) {
      setText(errSignIn, err?.message || 'Login failed');
      show(errSignIn);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
      }
    }
  }

  async function handleSignUp(e) {
    e.preventDefault();
    hide(errSignUp);
    setText(errSignUp, '');

    const username = $('#signUpUsername')?.value?.trim() || '';
    const email = $('#signUpEmail')?.value?.trim() || '';
    const password = $('#signUpPassword')?.value || '';

    if (!username || !email || !password) {
      setText(errSignUp, 'Please fill in all fields.');
      show(errSignUp);
      return;
    }

    const btn = $('#signUpBtn');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
    }

    try {
      const data = await apiJson('/api/auth/register', { username, email, password });
      if (!data?.success) throw new Error(data?.error || 'Registration failed');

      // Require email verification before sign-in
      window.location.href = '/login?check_email=1';
    } catch (err) {
      setText(errSignUp, err?.message || 'Registration failed');
      show(errSignUp);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.classList.remove('loading');
      }
    }
  }

  // Bind
  openBtns.forEach((b) => {
    b.addEventListener('click', (e) => {
      e.preventDefault();
      const mode = b.getAttribute('data-auth-open') || 'signin';
      openSheet(mode);
    });
  });

  closeBtn?.addEventListener('click', closeSheet);
  backdrop?.addEventListener('click', closeSheet);

  tabSignIn?.addEventListener('click', () => selectMode('signin'));
  tabSignUp?.addEventListener('click', () => selectMode('signup'));

  formSignIn?.addEventListener('submit', handleSignIn);
  formSignUp?.addEventListener('submit', handleSignUp);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeSheet();
  });

  // Note: Do not auto-redirect from the homepage.
  // Redirect to dashboard happens only after successful auth.
})();
