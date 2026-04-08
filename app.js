const express = require("express");
const _ = require("lodash");
const axios = require("axios");

const app = express();
app.use(express.json());

// ------------------------------------------------------------------
// CVE-2021-23337 | lodash < 4.17.21 | Command Injection via template
// Severity: High | CVSS: 7.2
// lodash.template() executes arbitrary code when options.variable is
// supplied as a user-controlled value.
// ------------------------------------------------------------------
app.post("/render", (req, res) => {
  const { templateStr, variable } = req.body;

  // VULNERABLE: user-controlled `variable` passed directly into options
  const compiled = _.template(templateStr, { variable });
  const output = compiled({ user: "guest" });

  res.send({ result: output });
});

// ------------------------------------------------------------------
// CVE-2020-28168 | axios < 0.21.1 | SSRF
// Severity: Medium | CVSS: 5.9
// axios follows redirects to internal hosts without restriction,
// enabling Server-Side Request Forgery when the URL is user-supplied.
// ------------------------------------------------------------------
app.get("/fetch", async (req, res) => {
  const { url } = req.query;

  // VULNERABLE: user-supplied URL passed directly to axios — no allowlist
  const response = await axios.get(url);
  res.send({ data: response.data });
});

// ------------------------------------------------------------------
// CVE-2022-24999 | express < 4.17.3 | qs Prototype Pollution
// Severity: High | CVSS: 7.5
// Malformed query strings like ?__proto__[admin]=true can pollute
// Object.prototype through the bundled qs parser.
// ------------------------------------------------------------------
app.get("/search", (req, res) => {
  // VULNERABLE: req.query parsed by the vulnerable qs version bundled with
  // express 4.17.1 — a crafted query string can pollute the prototype chain
  const filters = req.query;
  const results = Object.keys(filters).map((key) => ({
    field: key,
    value: filters[key],
  }));

  res.send({ results });
});

// ------------------------------------------------------------------
// Additional lodash usage — CVE-2020-8203 | Prototype Pollution
// Severity: High | CVSS: 7.4
// _.merge() with a user-supplied object can pollute Object.prototype
// ------------------------------------------------------------------
app.post("/merge-config", (req, res) => {
  const defaultConfig = { role: "viewer", theme: "light" };
  const userInput = req.body.config;

  // VULNERABLE: merging user-controlled object without sanitisation
  const finalConfig = _.merge({}, defaultConfig, userInput);

  res.send({ config: finalConfig });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
