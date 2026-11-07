// Runs before the stylesheet so a saved dark theme does not flash white.
(() => {
  const root = document.documentElement;
  const system = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  let preference = 'auto';
  try { preference = localStorage.getItem('kpm-theme') || 'auto'; } catch { /* Storage may be disabled by the host. */ }

  function apply(value) {
    preference = ['auto', 'light', 'dark'].includes(value) ? value : 'auto';
    const dark = preference === 'dark' || (preference === 'auto' && system?.matches);
    root.dataset.themePreference = preference;
    root.dataset.theme = dark ? 'dark' : 'light';
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? '#171a1b' : '#ffffff');
    document.dispatchEvent(new window.Event('kpm-theme-applied'));
  }

  apply(preference);
  document.addEventListener('kpm-theme-change', (e) => {
    apply(e.detail);
    try { localStorage.setItem('kpm-theme', preference); } catch { /* The current session still keeps its theme. */ }
  });
  system?.addEventListener('change', () => apply(preference));
  window.addEventListener('storage', (e) => { if (e.key === 'kpm-theme') apply(e.newValue); });
})();
