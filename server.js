import express from "express";
import cors from "cors";
import fetch from "node-fetch";
import crypto from "crypto";

const app  = express();
const PORT = process.env.PORT || 3000;

// ── ENV VARS (set in Render dashboard) ────────────────────────────────────────
// QBO_CLIENT_ID      — from Intuit Developer portal
// QBO_CLIENT_SECRET  — from Intuit Developer portal
// QBO_REDIRECT_URI   — https://jb-qbo-backend.onrender.com/callback
// FRONTEND_URL       — * (or restrict to your HTML file origin)
// QBO_SANDBOX        — false

const CLIENT_ID     = process.env.QBO_CLIENT_ID;
const CLIENT_SECRET = process.env.QBO_CLIENT_SECRET;
const REDIRECT_URI  = process.env.QBO_REDIRECT_URI;
const FRONTEND_URL  = process.env.FRONTEND_URL || "*";

const AUTH_URL     = "https://appcenter.intuit.com/connect/oauth2";
const TOKEN_URL    = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
const API_BASE     = "https://quickbooks.api.intuit.com/v3/company";
const SANDBOX_BASE = "https://sandbox-quickbooks.api.intuit.com/v3/company";
const SCOPES       = "com.intuit.quickbooks.accounting";

let tokenStore = {
  accessToken:  process.env.QBO_ACCESS_TOKEN  || null,
  refreshToken: process.env.QBO_REFRESH_TOKEN || null,
  realmId:      process.env.QBO_REALM_ID      || null,
  expiresAt:    null,
};

let oauthState = null;

// ── STRUCTURED LOGGER ─────────────────────────────────────────────────────────
function log(level, event, data = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, event, ...data }));
}

function logError(event, err, extra = {}) {
  log("ERROR", event, { message: err.message || String(err), stack: err.stack || null, ...extra });
}

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND_URL }));
app.use(express.json());
app.use((req, _res, next) => {
  log("INFO", "request", { method: req.method, path: req.path });
  next();
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function basicAuth() {
  return "Basic " + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
}

function apiBase() {
  return process.env.QBO_SANDBOX === "true" ? SANDBOX_BASE : API_BASE;
}

async function refreshIfNeeded() {
  if (!tokenStore.refreshToken) {
    const err = new Error("Not authenticated — visit /auth/start");
    logError("token_check", err);
    throw err;
  }
  if (tokenStore.expiresAt && Date.now() < tokenStore.expiresAt - 60000) return;

  log("INFO", "token_refresh_start");
  const res = await fetch(TOKEN_URL, {
    method:  "POST",
    headers: { "Authorization": basicAuth(), "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
    body:    new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokenStore.refreshToken }),
  });
  const intuitTid = res.headers.get("intuit_tid");
  if (!res.ok) {
    const body = await res.text();
    logError("token_refresh_failed", new Error(body), { status: res.status, intuit_tid: intuitTid });
    throw new Error("Token refresh failed: " + body);
  }
  const data = await res.json();
  tokenStore.accessToken  = data.access_token;
  tokenStore.refreshToken = data.refresh_token || tokenStore.refreshToken;
  tokenStore.expiresAt    = Date.now() + (data.expires_in * 1000);
  log("INFO", "token_refresh_ok", { intuit_tid: intuitTid, expires_in: data.expires_in });
}

async function qboGet(path) {
  await refreshIfNeeded();
  const url = `${apiBase()}/${tokenStore.realmId}${path}`;
  const res = await fetch(url, {
    headers: { "Authorization": `Bearer ${tokenStore.accessToken}`, "Accept": "application/json" },
  });
  const intuitTid = res.headers.get("intuit_tid");
  log("INFO", "qbo_response", { status: res.status, intuit_tid: intuitTid, path });
  if (!res.ok) {
    const body = await res.text();
    logError("qbo_api_error", new Error(body), { status: res.status, intuit_tid: intuitTid, path });
    const err = new Error(`QBO API error ${res.status}: ${body}`);
    err.intuitTid = intuitTid;
    err.status    = res.status;
    throw err;
  }
  return res.json();
}

// ── OAUTH ─────────────────────────────────────────────────────────────────────
app.get("/auth/start", (req, res) => {
  oauthState = crypto.randomBytes(16).toString("hex");
  log("INFO", "oauth_start");
  const params = new URLSearchParams({ client_id: CLIENT_ID, response_type: "code", scope: SCOPES, redirect_uri: REDIRECT_URI, state: oauthState });
  res.redirect(`${AUTH_URL}?${params}`);
});

app.get("/callback", async (req, res) => {
  const { code, state, realmId, error } = req.query;
  if (error) { logError("oauth_error", new Error(error)); return res.status(400).send(`OAuth error: ${error}`); }
  if (state !== oauthState) { logError("oauth_csrf", new Error("State mismatch")); return res.status(403).send("State mismatch — possible CSRF"); }

  const tokenRes = await fetch(TOKEN_URL, {
    method:  "POST",
    headers: { "Authorization": basicAuth(), "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
    body:    new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI }),
  });
  const intuitTid = tokenRes.headers.get("intuit_tid");
  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    logError("oauth_token_exchange_failed", new Error(body), { status: tokenRes.status, intuit_tid: intuitTid });
    return res.status(400).send("Token exchange failed: " + body);
  }
  const data = await tokenRes.json();
  tokenStore.accessToken  = data.access_token;
  tokenStore.refreshToken = data.refresh_token;
  tokenStore.realmId      = realmId;
  tokenStore.expiresAt    = Date.now() + (data.expires_in * 1000);
  log("INFO", "oauth_success", { realmId, intuit_tid: intuitTid });
  res.send(`<html><body style="font-family:sans-serif;padding:2rem;max-width:500px;margin:auto">
    <h2 style="color:#1b3a5c">Connected to QuickBooks!</h2>
    <p>Vernon Inc dba James Blinds is now linked. You can close this tab and return to the AIA app.</p>
    <p style="color:#888;font-size:13px;margin-top:1rem">Realm ID: ${realmId}</p>
  </body></html>`);
});

app.get("/auth/status", (req, res) => res.json({ connected: !!tokenStore.accessToken, realmId: tokenStore.realmId }));

app.post("/auth/disconnect", (req, res) => {
  log("INFO", "auth_disconnect");
  tokenStore = { accessToken: null, refreshToken: null, realmId: null, expiresAt: null };
  res.json({ ok: true });
});

// ── QBO ROUTES ────────────────────────────────────────────────────────────────
app.get("/qbo/customers", async (req, res) => {
  try {
    const data = await qboGet("/query?query=SELECT%20*%20FROM%20Customer%20WHERE%20Active%20%3D%20true%20MAXRESULTS%20200&minorversion=65");
    const customers = (data.QueryResponse.Customer || []).map(c => ({
      id:          c.Id,
      name:        c.DisplayName,
      companyName: c.CompanyName || c.DisplayName,
      email:       c.PrimaryEmailAddr?.Address || "",
      phone:       c.PrimaryPhone?.FreeFormNumber || "",
      address:     c.BillAddr ? [c.BillAddr.Line1, c.BillAddr.City, c.BillAddr.CountrySubDivisionCode, c.BillAddr.PostalCode].filter(Boolean).join(", ") : "",
      balance:     c.Balance || 0,
    }));
    log("INFO", "customers_fetched", { count: customers.length });
    res.json({ customers });
  } catch(e) {
    logError("customers_error", e);
    res.status(e.status || 500).json({ error: e.message, intuit_tid: e.intuitTid || null });
  }
});

app.get("/qbo/customers/:id", async (req, res) => {
  try {
    const data = await qboGet(`/customer/${req.params.id}?minorversion=65`);
    const c = data.Customer;
    res.json({ id: c.Id, name: c.DisplayName, companyName: c.CompanyName || c.DisplayName, email: c.PrimaryEmailAddr?.Address || "", phone: c.PrimaryPhone?.FreeFormNumber || "", address: c.BillAddr ? [c.BillAddr.Line1, c.BillAddr.City, c.BillAddr.CountrySubDivisionCode, c.BillAddr.PostalCode].filter(Boolean).join(", ") : "", balance: c.Balance || 0 });
  } catch(e) {
    logError("customer_detail_error", e, { id: req.params.id });
    res.status(e.status || 500).json({ error: e.message, intuit_tid: e.intuitTid || null });
  }
});

app.get("/qbo/invoices", async (req, res) => {
  try {
    const { customerId } = req.query;
    const query = customerId
      ? `SELECT * FROM Invoice WHERE CustomerRef = '${customerId}' ORDERBY TxnDate DESC MAXRESULTS 50`
      : `SELECT * FROM Invoice ORDERBY TxnDate DESC MAXRESULTS 100`;
    const data = await qboGet(`/query?query=${encodeURIComponent(query)}&minorversion=65`);
    const invoices = (data.QueryResponse.Invoice || []).map(inv => ({
      id: inv.Id, docNumber: inv.DocNumber, txnDate: inv.TxnDate, dueDate: inv.DueDate || "",
      customerName: inv.CustomerRef?.name || "", customerId: inv.CustomerRef?.value || "",
      amount: inv.TotalAmt || 0, balance: inv.Balance || 0, memo: inv.CustomerMemo?.value || "",
      lineItems: (inv.Line || [])
        .filter(l => l.DetailType === "SalesItemLineDetail" || l.DetailType === "GroupLineDetail")
        .map(l => ({ description: l.Description || l.SalesItemLineDetail?.ItemRef?.name || "", amount: l.Amount || 0, qty: l.SalesItemLineDetail?.Qty || 1, unitPrice: l.SalesItemLineDetail?.UnitPrice || l.Amount || 0 })),
    }));
    log("INFO", "invoices_fetched", { count: invoices.length, customerId: customerId || "all" });
    res.json({ invoices });
  } catch(e) {
    logError("invoices_error", e, { customerId: req.query.customerId });
    res.status(e.status || 500).json({ error: e.message, intuit_tid: e.intuitTid || null });
  }
});

app.get("/qbo/invoices/:id", async (req, res) => {
  try {
    const data = await qboGet(`/invoice/${req.params.id}?minorversion=65`);
    const inv = data.Invoice;
    res.json({
      id: inv.Id, docNumber: inv.DocNumber, txnDate: inv.TxnDate, dueDate: inv.DueDate || "",
      customerName: inv.CustomerRef?.name || "", customerId: inv.CustomerRef?.value || "",
      amount: inv.TotalAmt || 0, balance: inv.Balance || 0, memo: inv.CustomerMemo?.value || "",
      shipAddr: inv.ShipAddr ? [inv.ShipAddr.Line1, inv.ShipAddr.City, inv.ShipAddr.CountrySubDivisionCode].filter(Boolean).join(", ") : "",
      lineItems: (inv.Line || [])
        .filter(l => l.DetailType === "SalesItemLineDetail")
        .map(l => ({ description: l.Description || l.SalesItemLineDetail?.ItemRef?.name || "", amount: l.Amount || 0, qty: l.SalesItemLineDetail?.Qty || 1, unitPrice: l.SalesItemLineDetail?.UnitPrice || 0 })),
    });
  } catch(e) {
    logError("invoice_detail_error", e, { id: req.params.id });
    res.status(e.status || 500).json({ error: e.message, intuit_tid: e.intuitTid || null });
  }
});

// ── HEALTH + GLOBAL ERROR HANDLER ─────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ok", service: "JamesBlinds QBO API", connected: !!tokenStore.accessToken }));

app.use((err, req, res, _next) => {
  logError("unhandled_error", err, { path: req.path });
  res.status(500).json({ error: "Internal server error", message: err.message });
});

app.listen(PORT, () => log("INFO", "server_start", { port: PORT }));
