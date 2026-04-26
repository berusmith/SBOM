// Reachable use of res.redirect with user-controlled URL —
// CVE-2024-29041 open redirect via encodeurl bypass.
const express = require('express');

const app = express();

app.get('/go', (req, res) => {
  // req.query.url originates from the request — pre-4.19.2 Express
  // would encode it through encodeurl in a way that can bypass
  // redirect allowlist checks.
  res.redirect(req.query.url);
});

app.get('/profile/:id', (req, res) => {
  // res.location is the underlying primitive that res.redirect
  // calls into.  Same CVE applies to direct res.location use.
  res.location(`/users/${req.params.id}`).status(302).end();
});

module.exports = app;
