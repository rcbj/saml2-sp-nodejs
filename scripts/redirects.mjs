// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The entityID and the assertion consumer URL the demo registers, and the ones it serves, are the
// same addresses. A loopback URL follows the port the demo listens on. Any other host is left as written.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1']);

/** Replace the port of a loopback URL. Anything else is returned unchanged. */
export function onPort(url, port) {
  const next = new URL(url);
  // URL.hostname keeps the brackets on an IPv6 address: [::1], not ::1.
  const host = next.hostname.startsWith('[') ? next.hostname.slice(1, -1) : next.hostname;
  if (!LOOPBACK.has(host)) return url;
  next.port = String(port);
  return next.href;
}

/**
 * The entityID and assertion consumer URL to register.
 * An explicit public URL replaces the origin and keeps the path.
 * Otherwise `port` moves a loopback URL onto the port the demo listens on.
 */
export function endpointsFor(entityId, acsUrl, options) {
  if (options.publicUrlGiven && options.publicUrl) {
    const base = new URL(options.publicUrl.endsWith('/') ? options.publicUrl : `${options.publicUrl}/`);
    const move = (value) => {
      const next = new URL(value);
      next.protocol = base.protocol;
      next.hostname = base.hostname;
      next.port = base.port;
      return next.href;
    };
    return { entityId: move(entityId), acsUrl: move(acsUrl) };
  }
  if (options.port) {
    return { entityId: onPort(entityId, options.port), acsUrl: onPort(acsUrl, options.port) };
  }
  return { entityId, acsUrl };
}

function parsePort(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return undefined;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return port;
}

/** The container's PORT wins when it is a port. Otherwise the environment. An unusable value is absent. */
export function demoPort(envPort, containerPort) {
  return parsePort(containerPort) ?? parsePort(envPort);
}
