// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The signed-in page's one script: it listens on /events for what the server's Shared Signals receiver
// did to this tab's session. The SESSION is already gone on the server when `signed-out` arrives; this
// only tells the person and takes them back to the sign-in page.
const banner = document.getElementById('signal-banner');
const events = new EventSource('/events');
events.addEventListener('signed-out', (e) => {
  const { type, reason } = JSON.parse(e.data);
  banner.textContent = `You were signed out: the identity provider sent ${type}${reason ? ` (${typeof reason === 'object' ? Object.values(reason)[0] : reason})` : ''}.`;
  banner.hidden = false;
  events.close();
  setTimeout(() => { location.href = '/'; }, 4000);
});
events.addEventListener('signal', () => { location.reload(); });
