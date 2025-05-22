// cspMiddleware.js
// Middleware to add Content Security Policy headers

function cspMiddleware(req, res, next) {
  const cspDirectives = {
    "default-src": "'self'",
    "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",
    "style-src": "'self' 'unsafe-inline'",
    "img-src": "'self' data:",
    "connect-src": "'self'",
    "font-src": "'self'",
    "object-src": "'none'",
    "frame-ancestors": "'none'",
    "base-uri": "'self'"
  };
  const cspHeader = Object.entries(cspDirectives)
    .map(([k, v]) => `${k} ${v}`)
    .join('; ');
  res.setHeader('Content-Security-Policy', cspHeader);
  next();
}

module.exports = cspMiddleware;