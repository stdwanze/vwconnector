const request = require("request");
const AdmZip = require("adm-zip");
const { v4: uuidv4 } = require("uuid");

const BASE_URL = "https://eu-data-act.drivesomethinggreater.com";
const IDENTITY_BASE = "https://identity.vwgroup.io";
const OIDC_AUTHORIZE_URL = IDENTITY_BASE + "/oidc/v1/authorize";
const OIDC_SCOPE = "openid cars profile";
const OIDC_REDIRECT_URI = BASE_URL + "/login";
const USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

// Per-brand OIDC client IDs (from ioBroker.vw-connect)
const BRAND_CLIENT_IDS = {
    VOLKSWAGEN_PASSENGER_CARS: "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com",
    VOLKSWAGEN_COMMERCIAL_VEHICLES: "9b58543e-1c15-4193-91d5-8a14145bebb0@apps_vw-dilab_com",
    AUDI: "cc29b87a-5e9a-4362-aecf-5adea6b01bbb@apps_vw-dilab_com",
    BENTLEY: "d38aac0f-3d89-4a63-8538-b75b31322c7b@apps_vw-dilab_com",
    SKODA: "3ea88bf9-1d4e-4a68-b3ad-4098c1f1d246@apps_vw-dilab_com",
    SEAT: "f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com",
    CUPRA: "f85e5b69-e3b2-43aa-9c0d-1b7d0e0b576f@apps_vw-dilab_com",
};

const VEHICLES_PATH = "/proxy_api/consent/me/vehicles";
const RELATION_PATH = "/proxy_api/vum/v2/users/me/relations/{vin}";
const METADATA_PATH = "/proxy_api/euda-apim/datarequest/vehicles/{vin}/metadata/partial";
const LIST_PATH = "/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{identifier}/list";
const DOWNLOAD_PATH = "/proxy_api/euda-apim/datadelivery/vehicles/{vin}/{identifier}/download";

class EuConnector {
    constructor(email, password, brand = "VOLKSWAGEN_PASSENGER_CARS", country = "de", language = "en", extraIdentifiers = []) {
        this.email = email;
        this.password = password;
        this.brand = brand;
        this.country = country;
        this.language = language;
        this.extraIdentifiers = extraIdentifiers;
        this.jar = request.jar();
        this.loggedIn = false;
    }

    _req(opts) {
        return new Promise((resolve, reject) => {
            request({ jar: this.jar, gzip: true, followAllRedirects: true, ...opts }, (err, resp, body) => {
                if (err) return reject(err);
                resolve({ resp, body });
            });
        });
    }

    async _getText(url, headers = {}) {
        const { resp, body } = await this._req({
            method: "GET",
            url,
            headers: { "User-Agent": USER_AGENT, "Accept": "application/json, text/plain, */*", ...headers },
        });
        return { status: resp.statusCode, url: resp.request.uri.href, body: body || "" };
    }

    async _postForm(url, form, headers = {}) {
        const { resp, body } = await this._req({
            method: "POST",
            url,
            form,
            headers: { "User-Agent": USER_AGENT, ...headers },
        });
        return { status: resp.statusCode, url: resp.request.uri.href, body: body || "" };
    }

    async _getBuffer(url, headers = {}) {
        const { resp, body } = await this._req({
            method: "GET",
            url,
            encoding: null,
            headers: { "User-Agent": USER_AGENT, ...headers },
        });
        return { status: resp.statusCode, body };
    }

    async _getJson(url, headers = {}, retried = false) {
        const { status, body, url: finalUrl } = await this._getText(url, headers);

        // AEM session expiry: 5xx with HTML body
        if (status >= 500 && typeof body === "string" && body.trimStart().startsWith("<")) {
            console.log(`EU: 5xx+HTML at ${url} (HTTP ${status}), body: ${body.slice(0, 200)}`);
            if (!retried) {
                console.log(`EU: re-logging in and retrying...`);
                this.loggedIn = false;
                await this.login();
                return this._getJson(url, headers, true);
            }
            throw new Error(`EU: AEM session error at ${url} (HTTP ${status}) — body: ${body.slice(0, 200)}`);
        }

        if ((status === 401 || status === 403) && !retried) {
            console.log(`EU: session expired (${status}), re-logging in...`);
            this.loggedIn = false;
            await this.login();
            return this._getJson(url, headers, true);
        }

        if (status >= 400) throw new Error(`EU: GET ${url} -> HTTP ${status}`);

        try {
            return typeof body === "object" ? body : JSON.parse(body);
        } catch {
            throw new Error(`EU: invalid JSON from ${url}: ${String(body).slice(0, 100)}`);
        }
    }

    // ---- HTML parsing helpers ----

    _parseFirstForm(html) {
        const fields = {};
        let action = null;
        const formMatch = html.match(/<form[^>]*action=["']([^"']*)["']/i);
        if (formMatch) action = formMatch[1];
        const inputRegex = /<input[^>]*/gi;
        let m;
        while ((m = inputRegex.exec(html)) !== null) {
            const nameM = m[0].match(/name=["']([^"']*)["']/i);
            const valM = m[0].match(/value=["']([^"']*)["']/i);
            if (nameM) fields[nameM[1]] = valM ? valM[1] : "";
        }
        return { fields, action };
    }

    _extractTemplateModel(html) {
        const idx = html.indexOf("templateModel");
        if (idx === -1) return {};
        const brace = html.indexOf("{", idx);
        if (brace === -1) return {};
        let depth = 0;
        for (let i = brace; i < html.length; i++) {
            if (html[i] === "{") depth++;
            else if (html[i] === "}") {
                depth--;
                if (depth === 0) {
                    try { return JSON.parse(html.slice(brace, i + 1)); } catch { return {}; }
                }
            }
        }
        return {};
    }

    _extractCsrf(html) {
        const m = html.match(/csrf_token\s*[:=]\s*['"]([^'"]+)['"]/);
        return m ? m[1] : null;
    }

    _loginFields(html) {
        const { fields, action } = this._parseFirstForm(html);
        const model = this._extractTemplateModel(html);
        if (model.hmac) fields.hmac = model.hmac;
        if (model.relayState) fields.relayState = model.relayState;
        if (model.emailPasswordForm?.email) fields.email = fields.email || model.emailPasswordForm.email;
        const csrf = this._extractCsrf(html);
        if (csrf && !fields._csrf) fields._csrf = csrf;
        return { fields, action };
    }

    _resolveUrl(base, relative) {
        if (!relative) return base;
        try { return new URL(relative, base).toString(); } catch { return relative; }
    }

    _buildAuthorizeUrl() {
        const clientId = BRAND_CLIENT_IDS[this.brand] || BRAND_CLIENT_IDS.VOLKSWAGEN_PASSENGER_CARS;
        const state = `${this.country}__${this.language}__${this.brand}`;
        const params = new URLSearchParams({
            client_id: clientId,
            response_type: "code",
            scope: OIDC_SCOPE,
            state,
            redirect_uri: OIDC_REDIRECT_URI,
            prompt: "login",
        });
        return `${OIDC_AUTHORIZE_URL}?${params.toString()}`;
    }

    // ---- Auth ----

    async login() {
        console.log("EU: priming session...");
        try { await this._getText(BASE_URL + "/"); } catch {}

        const authorizeUrl = this._buildAuthorizeUrl();
        console.log("EU: starting OIDC flow...");
        const signin = await this._getText(authorizeUrl);
        const signinUrl = signin.url;
        const signinHtml = signin.body;

        const { fields, action } = this._loginFields(signinHtml);
        if (!fields.hmac || !fields._csrf) {
            throw new Error(`EU: cannot parse sign-in form. Fields: ${Object.keys(fields).join(", ")}`);
        }
        fields.email = this.email;

        const identifierAction = this._resolveUrl(signinUrl, action);
        const identResp = await this._postForm(identifierAction, fields, { Referer: signinUrl });
        const authenticateUrl = identResp.url;
        const authenticateHtml = identResp.body;

        const { fields: fields2, action: action2 } = this._loginFields(authenticateHtml);
        if (!fields2.hmac || !fields2._csrf) {
            throw new Error("EU: cannot parse password form — check email address");
        }
        fields2.email = this.email;
        fields2.password = this.password;

        const authenticateAction = action2
            ? this._resolveUrl(authenticateUrl, action2).split("?")[0]
            : authenticateUrl.split("?")[0];

        console.log("EU: posting credentials...");
        const landing = await this._postForm(authenticateAction, fields2, { Referer: authenticateUrl });

        if (landing.status >= 400) {
            throw new Error(`EU: login rejected (HTTP ${landing.status})`);
        }

        const landingUrl = landing.url;
        if (landingUrl.includes("signin-service") || landingUrl.includes("/error")) {
            throw new Error("EU: login failed — check email and password");
        }

        const portalHost = new URL(BASE_URL).hostname;
        if (new URL(landingUrl).hostname !== portalHost) {
            throw new Error(`EU: login did not complete (ended at ${landingUrl})`);
        }

        console.log("EU: authenticated");
        this.loggedIn = true;
    }

    async ensureLogin() {
        if (!this.loggedIn) await this.login();
    }

    // ---- Vehicle + data API ----

    _extractVins(payload) {
        const vins = {};
        const walk = (node) => {
            if (!node || typeof node !== "object") return;
            if (Array.isArray(node)) { node.forEach(walk); return; }
            const vin = node.vin || node.vehicleIdentificationNumber;
            if (typeof vin === "string" && vin.length === 17) {
                if (!vins[vin]) vins[vin] = { vin };
                const nick = node.vehicleNickname || node.nickname || node.modelName;
                if (nick) vins[vin].nickname = nick;
            }
            Object.values(node).forEach(walk);
        };
        walk(payload);
        return Object.values(vins);
    }

    async getVehicles() {
        await this.ensureLogin();
        const payload = await this._getJson(`${BASE_URL}${VEHICLES_PATH}?viewPosition=FRONT_LEFT`);
        const vehicles = this._extractVins(payload);
        for (const veh of vehicles) {
            try {
                const url = `${BASE_URL}${RELATION_PATH.replace("{vin}", veh.vin)}`;
                const rel = await this._getJson(url, { traceid: `vehicle-relation-fetch-${uuidv4()}` });
                const nick = (rel.relation || {}).vehicleNickname;
                if (nick) veh.nickname = nick;
            } catch {}
        }
        return vehicles;
    }

    async getMetadata(vin) {
        await this.ensureLogin();
        const url = `${BASE_URL}${METADATA_PATH.replace("{vin}", vin)}`;
        const { status, body } = await this._getText(url);
        if (status === 404) {
            throw new Error(
                `EU: no data request found for VIN ${vin} (HTTP 404).\n` +
                `  → Log into the portal, select the vehicle, and create a data request first.\n` +
                `  → Then wait ~15 min for the first dataset to generate.`
            );
        }
        if (status >= 400) throw new Error(`EU: GET ${url} -> HTTP ${status}`);
        try { return typeof body === "object" ? body : JSON.parse(body); }
        catch { throw new Error(`EU: invalid JSON from ${url}`); }
    }

    async listDatasets(vin, identifier) {
        await this.ensureLogin();
        const url = `${BASE_URL}${LIST_PATH.replace("{vin}", vin).replace("{identifier}", identifier)}`;
        const { status, body } = await this._getText(url, { type: "partial" });
        if (status === 404) return []; // no datasets generated yet
        if (status >= 400) throw new Error(`EU: GET ${url} -> HTTP ${status}`);
        try {
            const data = typeof body === "object" ? body : JSON.parse(body);
            return Array.isArray(data) ? data : (data.files || []);
        } catch { throw new Error(`EU: invalid JSON from ${url}`); }
    }

    async downloadDataset(vin, identifier, name, retried = false) {
        await this.ensureLogin();
        if (name.endsWith("_no_content_found.zip")) throw new Error(`${name}: no content`);

        const url = `${BASE_URL}${DOWNLOAD_PATH.replace("{vin}", vin).replace("{identifier}", identifier)}`;
        const { status, body } = await this._getBuffer(url, { filename: name, type: "partial" });

        // AEM session expiry
        if (status >= 500 && body && body.toString().trimStart().startsWith("<") && !retried) {
            this.loggedIn = false;
            await this.login();
            return this.downloadDataset(vin, identifier, name, true);
        }
        if (status >= 400) throw new Error(`EU: download ${name} -> HTTP ${status}`);

        const zip = new AdmZip(Buffer.isBuffer(body) ? body : Buffer.from(body));
        const entries = zip.getEntries().filter(e => e.entryName.toLowerCase().endsWith(".json"));
        if (!entries.length) throw new Error(`EU: no JSON found in ${name}`);
        return JSON.parse(entries[0].getData().toString("utf-8"));
    }

    async _tryGetIdentifiers(vin, suffix) {
        const url = `${BASE_URL}/proxy_api/euda-apim/datarequest/vehicles/${vin}/metadata${suffix ? "/" + suffix : ""}`;
        const { status, body } = await this._getText(url);
        if (status === 404 || status >= 400) return [];
        try {
            const parsed = typeof body === "object" ? body : JSON.parse(body);
            console.log(`EU: /metadata${suffix ? "/" + suffix : ""} (${status}): ${JSON.stringify(parsed).slice(0, 300)}`);
            // Single product
            if (parsed.identifier) return [parsed.identifier];
            if (parsed.Identifier) return [parsed.Identifier];
            // Array of products
            if (Array.isArray(parsed)) return parsed.map(p => p.identifier || p.Identifier).filter(Boolean);
            // Nested: { products: [...] } or similar
            const nested = parsed.products || parsed.items || parsed.dataRequests || parsed.requests;
            if (Array.isArray(nested)) return nested.map(p => p.identifier || p.Identifier).filter(Boolean);
            return [];
        } catch { return []; }
    }

    async _tryListDatasets(vin, identifier, label) {
        try {
            const datasets = await this.listDatasets(vin, identifier);
            const noContent = datasets.filter(d => d.name?.endsWith("_no_content_found.zip"));
            const available = datasets.filter(d => !d.name?.endsWith("_no_content_found.zip"));
            const latestAny = [...datasets].sort((a, b) => new Date(b.createdOn) - new Date(a.createdOn))[0];
            console.log(`EU [${label}]: ${datasets.length} ZIP(s) — ${available.length} with data, ${noContent.length} no_content_found`);
            if (latestAny) console.log(`EU [${label}]: newest: ${latestAny.name} (created: ${latestAny.createdOn})`);
            return { available, total: datasets.length, identifier };
        } catch (e) {
            console.log(`EU [${label}]: list failed — ${e.message}`);
            return { available: [], total: 0, identifier };
        }
    }

    async getLatestData(vin) {
        // Collect all identifiers from known metadata endpoints
        const seen = new Set();
        const candidates = []; // { identifier, label }

        for (const suffix of ["partial", "full", ""]) {
            const ids = await this._tryGetIdentifiers(vin, suffix);
            for (const id of ids) {
                if (!seen.has(id)) {
                    seen.add(id);
                    candidates.push({ identifier: id, label: suffix || "none" });
                }
            }
        }

        // Append manually configured identifiers (e.g. Request File) not discoverable via metadata
        for (const id of this.extraIdentifiers) {
            if (!seen.has(id)) {
                seen.add(id);
                candidates.push({ identifier: id, label: "config" });
            }
        }

        if (!candidates.length) {
            throw new Error("EU: no data products found. Register on the portal and create a data request first.");
        }

        // Try each candidate; return first with real data
        for (const { identifier, label } of candidates) {
            const { available, total } = await this._tryListDatasets(vin, identifier, label);
            if (available.length) {
                const latest = available.sort((a, b) => new Date(b.createdOn) - new Date(a.createdOn))[0];
                console.log(`EU: downloading from product "${label}" (${identifier})...`);
                return this.downloadDataset(vin, identifier, latest.name);
            }
            const reason = total === 0
                ? "no files yet (wait for next 15-min cycle)"
                : "all files are no_content_found";
            console.log(`EU [${label}]: ${reason}, trying next...`);
        }
        throw new Error("EU: no data available yet — wait for the next 15-min cycle and try again.");
    }

    async run(vin = null) {
        await this.login();

        const vehicles = await this.getVehicles();
        console.log(`EU: found ${vehicles.length} vehicle(s):`);
        vehicles.forEach(v => console.log(`  - ${v.vin} (${v.nickname || "unknown"})`));

        if (!vehicles.length) return null;

        const target = vin ? vehicles.find(v => v.vin === vin) : vehicles[0];
        if (!target) throw new Error(`EU: VIN ${vin} not found`);

        console.log(`\nEU: fetching latest data for ${target.vin}...`);
        const data = await this.getLatestData(target.vin);
        console.log("EU data:", JSON.stringify(data, null, 2));
        return data;
    }
}

module.exports = EuConnector;
