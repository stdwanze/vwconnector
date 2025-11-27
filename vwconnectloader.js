
const request = require("request");
const crypto = require("crypto");
const { Crypto } = require("@peculiar/webcrypto");
const { v4: uuidv4 } = require("uuid");
const traverse = require("traverse");
const { extractKeys } = require("./lib/extractKeys");
const axios = require("axios").default;
const configloader = require('config');
const { savetokens, loadtokens} = require('./lib/tokenholder');
class VWConnector {

    constructor(options){

        this.configLoaded =  configloader.get('VW.creds');
        this.log = { error: function(msg){ console.log("error:" +msg);}, warn: function (msg) {console.log("WARN:"+msg);},debug: function (msg){ /*console.log("debug:" +msg);*/}, info: function(msg){console.log("info:" +msg);} };
        this.type = "Id";
        this.country = "DE";
        this.clientId = "a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com";
        this.xclientId = "";
        this.scope = "openid profile badge cars dealers birthdate vin";
        this.redirect = "weconnect://authenticated";
         this.androidPackageName = "com.volkswagen.weconnect";
        this.xrequest = "com.volkswagen.weconnect";
        this.responseType = "code id_token token";
        this.xappversion = "";
        this.xappname = "";
        this.jar = request.jar();
        this.config = {};
        this.config.password = this.configLoaded.password;
        this.config.user = this.configLoaded.user;
        this.config.type = "id";

    }
    extractKeys(adapter, path, element){
        const chargingstatus = element.chargingStatus;
        const batterystatus = element.batteryStatus;
        const plugstatus = element.plugStatus;
        const climatestatus = element.climatisationStatus;
        const rest = element;
        return {
            chargingstatus,batterystatus,plugstatus,climatestatus,element
        }

    }
    extractCodeFromUrl(url) {
    // Extract authorization code from weconnect:// URL
    // Can be in query string: weconnect://authenticated?code=eyJ...&state=abc123
    // Or in fragment: weconnect://authenticated#code=eyJ...&state=abc123
    try {
      this.log.debug("Extracting code from URL: " + url.substring(0, 150) + "...");

      const urlObj = new URL(url);

      // Try query string first
      let code = urlObj.searchParams.get("code");
      if (code) {
        this.log.debug("Extracted code from query string: " + code.substring(0, 50) + "...");
        return code;
      }

      // Try fragment (hash) - parse it like a query string
      if (urlObj.hash) {
        const fragment = urlObj.hash.substring(1); // Remove #
        const fragmentParams = new URLSearchParams(fragment);
        code = fragmentParams.get("code");
        if (code) {
          this.log.debug("Extracted code from fragment: " + code.substring(0, 50) + "...");
          return code;
        }

        // Also check for access_token in fragment (alternate OAuth flow)
        const accessToken = fragmentParams.get("access_token");
        if (accessToken) {
          this.log.debug("Found access_token in fragment instead of code");
          this.log.debug("This appears to be implicit flow, not authorization code flow");
          // Return null as we need 'code', not 'access_token'
        }
      }

      this.log.debug("No code parameter found in URL");
    } catch (error) {
      this.log.debug("Error parsing URL: " + error.message);
    }
    return null;
  }
    extractStateToken(body) {
    if (!body) return null;
    const stateMatch = body.match(/<input[^>]*name=["']state["'][^>]*value=["']([^"']*)["']/i);
    if (stateMatch && stateMatch[1]) {
      return stateMatch[1];
    }
    return null;
  }
    async followRedirectsManually(redirectUrl, depth, code_verifier, reject, resolve) {
      // Follow redirects manually until we hit weconnect:// (like Python does)
    const maxDepth = 10;

    if (depth >= maxDepth) {
      this.log.error("Too many redirects (max " + maxDepth + ")");
      reject();
      return;
    }

    // Check if we've reached weconnect:// URL
    if (redirectUrl.startsWith("weconnect://")) {
      this.log.debug("Reached weconnect:// URL: " + redirectUrl.substring(0, 100) + "...");
      const code = this.extractCodeFromUrl(redirectUrl);
      if (code) {
        this.log.debug("Successfully extracted authorization code (JWT token)");
        this.exchangeCodeForTokens(code, code_verifier, reject, resolve);
        return;
      } else {
        this.log.error("Could not extract code from weconnect:// URL");
        reject();
        return;
      }
    }

    // Continue following redirects
    this.log.debug("Redirect " + (depth + 1) + ": " + redirectUrl.substring(0, 100) + "...");

    try {
      // Get cookies from request jar
      const cookies = this.jar.getCookies(redirectUrl);
      const cookieHeader = cookies.map((c) => c.cookieString()).join("; ");

      const response = await axios({
        method: "get",
        url: redirectUrl,
        headers: {
          "User-Agent": this.userAgent,
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9",
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        maxRedirects: 0, // Don't follow redirects automatically
        validateStatus: (status) => status >= 200 && status < 400, // Accept redirects as valid
      });

      // Store any new cookies back into the jar
      if (response.headers["set-cookie"]) {
        response.headers["set-cookie"].forEach((cookie) => {
          this.jar.setCookie(cookie, redirectUrl);
        });
      }

      // Check for redirect response (302, 301, etc.)
      if (response.status >= 300 && response.status < 400) {
        const nextUrl = response.headers.location;

        if (!nextUrl) {
          this.log.error("Redirect response but no location header");
          reject();
          return;
        }

        // Check if this is a weconnect:// URL
        if (nextUrl.startsWith("weconnect://")) {
          this.log.debug("Found weconnect:// redirect: " + nextUrl.substring(0, 100) + "...");
          const code = this.extractCodeFromUrl(nextUrl);
          if (code) {
            this.log.debug("Successfully extracted authorization code (JWT token)");
            this.exchangeCodeForTokens(code, code_verifier, reject, resolve);
            return;
          }
        }

        // Check for error redirects
        if (nextUrl.includes("/error")) {
          this.log.error("Authentication error redirect: " + nextUrl);
          if (nextUrl.includes("error=access_denied")) {
            this.log.warn("========================================");
            this.log.warn("WICHTIG: Bitte loggen Sie sich einmal in der VW Connect App ein und akzeptieren Sie die neuen Nutzungsbedingungen.");
            this.log.warn("IMPORTANT: Please log in to the VW Connect App once and accept the new terms and conditions.");
            this.log.warn("========================================");
          }
          reject();
          return;
        }

        // Make relative URLs absolute
        let absoluteUrl = nextUrl;
        if (nextUrl.startsWith("/")) {
          const urlObj = new URL(redirectUrl);
          absoluteUrl = urlObj.protocol + "//" + urlObj.host + nextUrl;
        } else if (!nextUrl.startsWith("http") && !nextUrl.startsWith("weconnect://")) {
          absoluteUrl = redirectUrl + "/" + nextUrl;
        }

        // Continue following
        await this.followRedirectsManually(absoluteUrl, depth + 1, code_verifier, reject, resolve);
      } else if (response.status === 200) {
        // Check if we ended up at a consent/terms page
        if (response.data && (response.data.includes("termsAndConditions") || response.data.includes("consent"))) {
          this.log.warn("========================================");
          this.log.warn("WICHTIG: Bitte loggen Sie sich einmal in der VW Connect App ein und akzeptieren Sie die neuen Nutzungsbedingungen oder öffne die Final url im Browser.");
          this.log.warn("IMPORTANT: Please log in to the VW Connect App once and accept the new terms and conditions. Or open the final url in the browser.");
          this.log.warn("Final URL: " + redirectUrl);
          this.log.warn("========================================");
          reject();
          return;
        }

        this.log.error("Got 200 OK but expected redirect or weconnect:// URL");
        this.log.debug("Response body preview: " + (response.data ? response.data.substring(0, 200) : "empty"));
        reject();
      }
    } catch (error) {
      this.log.error("Error during redirect following: " + error.message);
      reject();
    }
  }
    async exchangeCodeForTokens(code, code_verifier, reject, resolve) {
    this.log.debug("Exchanging authorization code for tokens (Python-style, no code_verifier)");

    // CRITICAL: Use BFF token endpoint, NOT identity.vwgroup.io!
    // Python gets this from: https://emea.bff.cariad.digital/login/v1/idk/openid-configuration
    const tokenEndpoint = "https://emea.bff.cariad.digital/login/v1/idk/token";

    // Exchange code for tokens WITHOUT code_verifier (like Python does)
    const tokenBody = {
      client_id: this.clientId,
      grant_type: "authorization_code",
      code: code,
      redirect_uri: this.redirect,
      // NO code_verifier - Python doesn't use it!
    };

    try {
      // Get cookies from jar for this request
      const cookies = this.jar.getCookies(tokenEndpoint);
      const cookieHeader = cookies.map((c) => c.cookieString()).join("; ");

      const response = await axios({
        method: "post",
        url: tokenEndpoint,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": this.userAgent,
          "Accept": "application/json",
          "Accept-Language": "en-US,en;q=0.9",
          ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        },
        data: new URLSearchParams(tokenBody).toString(),
        maxRedirects: 0,
      });

      // Store any new cookies back into the jar
      if (response.headers["set-cookie"]) {
        response.headers["set-cookie"].forEach((cookie) => {
          this.jar.setCookie(cookie, tokenEndpoint);
        });
      }

      this.log.debug("Token exchange successful");
      const tokens = response.data;

      // Store tokens directly like Python does
      this.config.atoken = tokens.access_token;
      this.config.rtoken = tokens.refresh_token;

      this.log.debug("Tokens received and stored, continuing with VW-specific flow");

      // Continue with VW-specific token handling
      await this.getVWToken(tokens, tokens.id_token, reject, resolve);
    } catch (error) {
      this.log.error("Failed to exchange code for tokens at OpenID endpoint");
      if (error.response) {
        this.log.error("Status: " + error.response.status);
        this.log.error("Response: " + JSON.stringify(error.response.data));
      } else {
        this.log.error(error.message);
      }
      reject();
    }
  }

    login() {
        return new Promise(async (resolve, reject) => {

            const tokens = loadtokens();
            if(tokens != null){
                this.config.atoken = tokens.atoken;
                this.config.refreshToken = tokens.refreshtoken;
                console.log("tokenfound");
                resolve();
                return;
            }


          const nonce = this.getNonce();
          const state = uuidv4();
          this.log.info(`Login in with ${this.config.type}`);
          let [code_verifier, codeChallenge] = this.getCodeChallenge();
          if (this.config.type === "seatelli" || this.config.type === "skodapower") {
            [code_verifier, codeChallenge] = this.getCodeChallengev2();
          }
          const method = "GET";
          const form = {};
          let url =
            "https://identity.vwgroup.io/oidc/v1/authorize?client_id=" +
            this.clientId +
            "&scope=" +
            this.scope +
            "&response_type=" +
            this.responseType +
            "&redirect_uri=" +
            this.redirect +
            "&nonce=" +
            nonce +
            "&state=" +
            state;
          if (
            this.config.type === "vw" ||
            this.config.type === "vwv2" ||
            this.config.type === "go" ||
            this.config.type === "seatelli" ||
            this.config.type === "skodapower" ||
            this.config.type === "audidata" ||
            this.config.type === "audietron" ||
            this.config.type === "seatcupra"
          ) {
            url += "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
          }
          if (this.config.type === "audi") {
            url += "&ui_locales=de-DE%20de&prompt=login";
          }
          if (this.config.type === "id" && this.type !== "Wc") {
            url = await this.receiveLoginUrl().catch(() => {
              this.log.warn("Failed to get login url");
            });
            if (!url) {
              url =
                "https://emea.bff.cariad.digital/user-login/v1/authorize?nonce=" +
                this.randomString(16) +
                "&redirect_uri=weconnect://authenticated";
            }
          }
        
          
          const loginRequest = request(
            {
              method: method,
              url: url,
              headers: {
                "User-Agent": this.userAgent,
                Accept:
                  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "x-requested-with": this.xrequest,
                "upgrade-insecure-requests": 1,
              },
              jar: this.jar,
              form: form,
              gzip: true,
              followAllRedirects: true,
            },
            (err, resp, body) => {
              if (err || (resp && resp.statusCode >= 400)) {
                if (this.type === "Wc") {
                  if (err && err.message && err.message === "Invalid protocol: wecharge:") {
                    this.log.debug("Found WeCharge connection");
                    this.getTokens(loginRequest, code_verifier, reject, resolve);
                  } else {
                    this.log.debug("No WeCharge found, cancel login");
                    resolve();
                  }
                  return;
                }
                if (err && err.message && err.message.indexOf("Invalid protocol:") !== -1) {
                  this.log.debug("Found Token");
                  this.getTokens(loginRequest, code_verifier, reject, resolve);
                  return;
                }
                this.log.error("Failed in first login step ");
                err && this.log.error(err);
                resp && this.log.error(resp.statusCode.toString());
                body && this.log.error(JSON.stringify(body));
                err && err.message && this.log.error(err.message);
                loginRequest &&
                  loginRequest.uri &&
                  loginRequest.uri.query &&
                  this.log.debug(loginRequest.uri.query.toString());
    
                reject();
                return;
              }
    
              try {
                  const stateToken = this.extractStateToken(body);

            // New authentication flow with state token
            if (stateToken) {
              this.log.info("Using new authentication flow with state token");
              const loginForm = {
                username: this.config.user,
                password: this.config.password,
                state: stateToken
              };

              const loginHeaders = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": this.userAgent,
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "x-requested-with": this.xrequest,
              };

              if (this.config.type === "id" && this.androidPackageName) {
                loginHeaders["x-android-package-name"] = this.androidPackageName;
              }

              request.post(
                {
                  url: "https://identity.vwgroup.io/u/login?state=" + stateToken,
                  headers: loginHeaders,
                  form: loginForm,
                  jar: this.jar,
                  gzip: true,
                  followAllRedirects: false, // Follow redirects manually
                },
                (err, resp, _body) => {
                  if (err || (resp && resp.statusCode >= 400)) {
                    this.log.error("Failed new authentication flow");
                    err && this.log.error(err.message);
                    resp && this.log.error("Status: " + resp.statusCode);
                    reject();
                    return;
                  }

                  try {
                    // Follow redirects manually like Python does
                    if (!resp.headers.location) {
                      this.log.error("No redirect location in response");
                      reject();
                      return;
                    }

                    let redirectUrl = resp.headers.location;
                    if (redirectUrl.startsWith("/")) {
                      redirectUrl = "https://identity.vwgroup.io" + redirectUrl;
                    }

                    this.log.debug("Starting manual redirect following from: " + redirectUrl.substring(0, 100));

                    // Follow redirects manually until we hit weconnect://
                    this.followRedirectsManually(redirectUrl, 0, code_verifier, reject, resolve);
                  } catch (err) {
                    this.log.error("Error processing new auth response");
                    this.log.error(err);
                    reject();
                  }
                }
              );
              return;
            }
              } catch (err) {
                this.log.error(err);
                reject();
              }
            },
          );
        });
      }
      receiveLoginUrl() {
        return new Promise((resolve, reject) => {
          request(
            {
              method: "GET",
              url:
                "https://emea.bff.cariad.digital/user-login/v1/authorize?nonce=" +
                this.randomString(16) +
                "&redirect_uri=weconnect://authenticated",
              headers: {
                "user-agent": this.userAgent,
                accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "accept-language": "de-de",
              },
              jar: this.jar,
              gzip: true,
              followAllRedirects: false,
            },
            (err, resp, body) => {
              if (err || (resp && resp.statusCode >= 400)) {
                this.log.error("Failed in receive login url ");
                err && this.log.error(err);
                resp && this.log.error(resp.statusCode.toString());
                body && this.log.error(JSON.stringify(body));
                reject();
                return;
              }
              resolve(resp.request.href);
            },
          );
        });
      }
    replaceVarInUrl(url, vin, tripType) {
        const curHomeRegion = this.homeRegion[vin];
        return url
            .replace("/$vin", "/" + vin + "")
            .replace("$homeregion/", curHomeRegion + "/")
            .replace("/$type/", "/" + this.type + "/")
            .replace("/$country/", "/" + this.country + "/")
            .replace("/$tripType", "/" + tripType);
    }
    getTokens(getRequest, code_verifier, reject, resolve) {
        if (this.config.type === "audietron") {
          this.getTokensv2(getRequest, code_verifier, reject, resolve);
          return;
        }
    
        let hash = "";
        if (getRequest.uri.hash) {
          hash = getRequest.uri.hash;
        } else {
          hash = getRequest.uri.query;
        }
        const hashArray = hash.split("&");
        // eslint-disable-next-line no-unused-vars
        let state;
        let jwtauth_code;
        let jwtaccess_token;
        let jwtid_token;
        let jwtstate;
        hashArray.forEach((hash) => {
          const harray = hash.split("=");
          if (harray[0] === "#state" || harray[0] === "state") {
            state = harray[1];
          }
          if (harray[0] === "code") {
            jwtauth_code = harray[1];
          }
          if (harray[0] === "access_token") {
            jwtaccess_token = harray[1];
          }
          if (harray[0] === "id_token") {
            jwtid_token = harray[1];
          }
          if (harray[0] === "#state") {
            jwtstate = harray[1];
          }
        });
        // const state = hashArray[0].substring(hashArray[0].indexOf("=") + 1);
        // const jwtauth_code = hashArray[1].substring(hashArray[1].indexOf("=") + 1);
        // const jwtaccess_token = hashArray[2].substring(hashArray[2].indexOf("=") + 1);
        // const jwtid_token = hashArray[5].substring(hashArray[5].indexOf("=") + 1);
        let method = "POST";
        let body = "auth_code=" + jwtauth_code + "&id_token=" + jwtid_token;
        let url = "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode";
        let headers = {
          // "user-agent": this.userAgent,
          "X-App-version": this.xappversion,
          "content-type": "application/x-www-form-urlencoded",
          "x-app-name": this.xappname,
          accept: "application/json",
        };
        if (this.config.type === "vw" || this.config.type === "vwv2") {
          body += "&code_verifier=" + code_verifier;
        } else {
          const brand = this.config.type === "skodae" ? "skoda" : this.config.type;
    
          body += "&brand=" + brand;
        }
        if (this.config.type === "skodae") {
          const parsedParameters = qs.parse(hash);
          this.config.atoken = parsedParameters.access_token;
          method = "POST";
          url = "https://api.connect.skoda-auto.cz/api/v1/authentication/token?systemId=TECHNICAL";
          body = JSON.stringify({
            authorizationCode: parsedParameters.code,
          });
          headers = {
            accept: "*/*",
            authorization: "Bearer " + parsedParameters.id_token,
            "content-type": "application/json",
            "user-agent": this.useragent,
            "accept-language": "de-de",
          };
        }
        if (this.config.type === "go") {
          url = "https://dmp.apps.emea.vwapps.io/mobility-platform/token";
          body =
            "code=" +
            jwtauth_code +
            "&client_id=" +
            this.clientId +
            "&redirect_uri=vwconnect://de.volkswagen.vwconnect/oauth2redirect/identitykit&grant_type=authorization_code&code_verifier=" +
            code_verifier;
        }
        if (this.config.type === "seatcupra") {
          url = "https://identity.vwgroup.io/oidc/v1/token";
          body =
            "code=" +
            jwtauth_code +
            "&client_id=" +
            this.clientId +
            "&redirect_uri=" +
            this.redirect +
            "&grant_type=authorization_code&code_verifier=" +
            code_verifier;
          headers = {
            accept: "*/*",
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            authorization:
              "Basic M2M3NTZkNDYtZjFiYS00ZDc4LTlmOWEtY2ZmMGQ1MjkyZDUxQGFwcHNfdnctZGlsYWJfY29tOmViODgxNGU2NDFjODFhMjY0MGFkNjJlZWNjZWMxMWM5OGVmZmM5YmNjZDQyNjlhYjdhZjMzOGI1MGE5NGIzYTI=",
            "user-agent": "CUPRAApp%20-%20Store/20220207 CFNetwork/1240.0.4 Darwin/20.6.0",
            "accept-language": "de-de",
          };
        }
        if (this.config.type === "audidata") {
          url = "https://audi-global-dmp.apps.emea.vwapps.io/mobility-platform/token";
          body =
            "code=" +
            jwtauth_code +
            "&client_id=" +
            this.clientId +
            "&redirect_uri=acpp://de.audi.connectplugandplay/oauth2redirect/identitykit&grant_type=authorization_code&code_verifier=" +
            code_verifier;
        }
        if (this.config.type === "id") {
          url = "https://emea.bff.cariad.digital/user-login/login/v1";
          let redirerctUri = "weconnect://authenticated";
    
          body = JSON.stringify({
            state: jwtstate,
            id_token: jwtid_token,
            redirect_uri: redirerctUri,
            region: "emea",
            access_token: jwtaccess_token,
            authorizationCode: jwtauth_code,
          });
          // @ts-ignore
          headers = {
            accept: "*/*",
            "content-type": "application/json",
            "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
            "user-agent": this.userAgent,
            "accept-language": "de-de",
          };
          if (this.type === "Wc") {
            method = "GET";
            url =
              "https://wecharge.apps.emea.vwapps.io/user-identity/v1/identity/login?redirect_uri=wecharge://authenticated&code=" +
              jwtauth_code;
            redirerctUri = "wecharge://authenticated";
            headers["x-api-key"] = "yabajourasW9N8sm+9F/oP==";
          }
        }
        if (this.config.type === "audi") {
          this.getVWToken({}, jwtid_token, reject, resolve);
          return;
        }
        if (this.config.type === "seatelli" || this.config.type === "skodapower") {
          url = "https://api.elli.eco/identity/v1/loginOrSignupWithIdKit";
          let brand = "seat";
          let redirect = "Seat-elli-hub://opid";
          if (this.config.type === "skodapower") {
            brand = "skoda";
            redirect = "skoda-hub://opid";
          }
          body = JSON.stringify({
            brand: brand,
            grant_type: "authorization_code",
            code: jwtauth_code,
            redirect_uri: redirect,
            code_verifier: code_verifier,
          });
          // @ts-ignore
          headers = {
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": this.userAgent,
            "Accept-Language": "de-DE",
          };
        }
        request(
          {
            method: method,
            url: url,
            headers: headers,
            body: body,
            jar: this.jar,
            gzip: true,
            followAllRedirects: false,
          },
          (err, resp, body) => {
            if (err || (resp && resp.statusCode >= 400)) {
              this.log.error("Failed to get token");
              err && this.log.error(err);
              resp && this.log.error(resp.statusCode.toString());
              body && this.log.error(JSON.stringify(body));
              reject();
              return;
            }
            try {
              const tokens = JSON.parse(body);
    
              this.getVWToken(tokens, jwtid_token, reject, resolve);
            } catch (err) {
              this.log.error(err);
              reject();
            }
          },
        );
      }
     
    async getVWToken(tokens, jwtid_token, reject, resolve) {
    if (this.config.type !== "audi" && this.config.type !== "audietron") {
      if (Object.keys(tokens).length > 0) {
        this.config.atoken = tokens.access_token || tokens.accessToken;
        this.config.rtoken = tokens.refresh_token || tokens.refreshToken;
      }
      if (this.config.type === "id" || this.config.type === "skodae") {
        this.log.info(`History limit: ${this.config.historyLimit}, set to -1 to disable wallcharging login`);
        if (this.config.historyLimit == -1) {
          this.log.info("History limit is set to -1, no wall charging login");
        } else {
          //check paired wallbox
          await axios({
            method: "get",
            maxBodyLength: Infinity,
            url: "https://prod.emea.mobile.charging.cariad.digital/headless/charging_stations/check_paired",
            headers: {
              "X-Api-Version": "1",
              traceparent: "00-96318317ce184ee8b7e9528586f4ffec-2b2afd705c4a4a58-01",
              Authorization: "Bearer " + this.config.atoken,
              Host: "prod.emea.mobile.charging.cariad.digital",
              Connection: "Keep-Alive",
              "User-Agent": "okhttp/4.12.0",
              "X-Debug-Log": "true",
              "Content-Type": "application/json",
              "Accept-Language": "de-DE",
              "X-Brand": this.xbrand,
              "X-Platform": "android",
              "X-Device-Timezone": "Europe/Berlin",
              "X-Sdk-Version": "4.5.4-(2025.18.0)",
              "X-Use-BffError-V2": "true",
              "X-Device-Manufacturer": "google",
              "X-Device-Name": "Pixel 4a",
              "X-Device-OS-Name": "13",
              "X-Device-OS-Version": "33",
            },
          })
            .then((response) => {
              if (response.data && response.data.hasPairedChargingStation) {
                this.log.info("Wallbox is paired");
                this.pairedWallbox = true;
                this.getWcData(this.config.historyLimit);
              } else {
                this.log.info("Wallbox is not paired");
              }
            })
            .catch((error) => {
              this.log.info('No wallbox found code: "' + error.response.status + '"');
              this.log.debug(error);
            });
        }
      }
      if (this.config.type === "id") {
        // Don't overwrite if already set from BFF token exchange
        if (!this.config.atoken) {
          this.config.atoken = tokens.access_token || tokens.accessToken;
        }
        if (!this.config.rtoken) {
          this.config.rtoken = tokens.refresh_token || tokens.refreshToken;
        }

        //configure for wallcharging login

        this.refreshTokenInterval = setInterval(() => {
          this.refreshIDToken().catch(() => {});
        }, 0.89 * 60 * 60 * 1000); // 0.89 hours
        this.log.info("ID login successfull");

        resolve();
        return;
      }

      if (this.clientId != "7f045eee-7003-4379-9968-9355ed2adb06@apps_vw-dilab_com") {
        this.secondAccessToken = tokens.accessToken;
        this.secondRefreshToken = tokens.refreshToken;
      }

      if (this.config.type === "seatelli" || this.config.type === "skodapower") {
        this.config.atoken = tokens.token;
      }
      if (this.config.type === "skodae") {
        if (this.refreshTokenInterval) {
          clearInterval(this.refreshTokenInterval);
        }
        this.refreshTokenInterval = setInterval(() => {
          this.refreshSkodaEToken().catch(() => {});
        }, 0.9 * 60 * 60 * 1000); // 0.9hours
        resolve();
        return;
      }
      if (this.config.type === "seatcupra") {
        if (this.refreshTokenInterval) {
          clearInterval(this.refreshTokenInterval);
        }
        this.refreshTokenInterval = setInterval(async () => {
          await this.refreshSeatCupraToken().catch(() => {});
        }, 0.935 * 60 * 60 * 1000); // 0.9hours
        resolve();
        return;
      }
      if (this.refreshTokenInterval) {
        clearInterval(this.refreshTokenInterval);
      }
      this.refreshTokenInterval = setInterval(() => {
        this.refreshToken().catch(() => {
          this.log.error("Refresh Token was not successful");
        });
        if (this.secondAccessToken) {
          this.refreshToken(null, true).catch(() => {
            this.log.error("Refresh Second Token was not successful");
          });
        }
      }, 0.9 * 60 * 60 * 1000); // 0.9hours
    }
    if (
      this.config.type === "go" ||
      this.config.type === "id" ||
      this.config.type === "skodae" ||
      this.config.type === "seatcupra" ||
      this.config.type === "seatelli" ||
      this.config.type === "skodapower" ||
      this.config.type === "audidata"
    ) {
      resolve();
      return;
    }
    request.post(
      {
        url: "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token",
        headers: {
          "User-Agent": this.userAgent,
          "X-App-Version": this.xappversion,
          "X-App-Name": this.xappname,
          "X-Client-Id": this.xclientId,
          Host: "mbboauth-1d.prd.ece.vwg-connect.com",
        },
        form: {
          grant_type: "id_token",
          token: jwtid_token || tokens.id_token,
          scope: "sc2:fal",
        },
        jar: this.jar,
        gzip: true,
        followAllRedirects: true,
      },
      (err, resp, body) => {
        if (err || (resp && resp.statusCode >= 400)) {
          this.log.error("Failed to get VWToken");
          err && this.log.error(err);
          resp && this.log.error(resp.statusCode.toString());
          body && this.log.error(JSON.stringify(body));
          resolve();
          return;
        }
        try {
          const tokens = JSON.parse(body);
          this.config.vwatoken = tokens.access_token;
          this.config.vwrtoken = tokens.refresh_token;
          if (this.vwrefreshTokenInterval) {
            clearInterval(this.vwrefreshTokenInterval);
          }
          this.vwrefreshTokenInterval = setInterval(() => {
            this.refreshToken(true).catch(() => {
              this.log.error("Refresh Token was not successful");
            });
          }, 0.9 * 60 * 60 * 1000); //0.9hours
          resolve();
        } catch (err) {
          this.log.error(err);
          reject();
        }
      },
    );
  }
    refreshToken(isVw) {
        let url = "https://tokenrefreshservice.apps.emea.vwapps.io/refreshTokens";
        let rtoken = this.config.rtoken;
        let body = "refresh_token=" + rtoken;
        let form = "";
        const brand = this.config.type === "skodae" ? "skoda" : this.config.type;

        body = "brand=" + brand + "&" + body;

        if (isVw) {
            url = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token";
            rtoken = this.config.vwrtoken;
            body = "grant_type=refresh_token&scope=sc2%3Afal&token=" + rtoken; //+ "&vin=" + vin;
        } else if (this.config.type === "go") {
            url = "https://dmp.apps.emea.vwapps.io/mobility-platform/token";
            body = "";
            // @ts-ignore
            form = {
                scope: "openid+profile+address+email+phone",
                client_id: this.clientId,
                grant_type: "refresh_token",
                refresh_token: rtoken,
            };
        }
        return new Promise((resolve, reject) => {
            this.log.debug("refreshToken ");
            this.log.debug(isVw ? "vw" : "");
            request.post(
                {
                    url: url,
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "content-type": "application/x-www-form-urlencoded",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        "X-Client-Id": this.xclientId,
                        accept: "application/json",
                    },
                    body: body,
                    form: form,
                    gzip: true,
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.log.error("Failing to refresh token. ");
                        this.log.error(isVw ? "VwToken" : "");
                        err && this.log.error(err);
                        body && this.log.error(body);
                        resp && this.log.error(resp.statusCode.toString());
                        setTimeout(() => {
                            this.log.error("Relogin");
                            this.login().catch(() => {
                                this.log.error("Failed relogin");
                            });
                        }, 1 * 60 * 1000);

                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        const tokens = JSON.parse(body);
                        if (tokens.error) {
                            this.log.error(JSON.stringify(body));
                            this.refreshTokenTimeout = setTimeout(() => {
                                this.refreshToken(isVw).catch(() => {
                                    this.log.error("refresh token failed");
                                });
                            }, 5 * 60 * 1000);
                            reject();
                            return;
                        }
                        if (isVw) {
                            this.config.vwatoken = tokens.access_token;
                            if (tokens.refresh_token) {
                                this.config.vwrtoken = tokens.refresh_token;
                            }
                        } else {
                            this.config.atoken = tokens.access_token;
                            if (tokens.refresh_token) {
                                this.config.rtoken = tokens.refresh_token;
                            }
                            if (tokens.accessToken) {
                                this.config.atoken = tokens.accessToken;
                                this.config.rtoken = tokens.refreshToken;
                            }
                        }
                        resolve();
                    } catch (err) {
                        this.log.error("Failing to parse refresh token. The instance will do restart and try a relogin.");
                        this.log.error(err);
                        this.log.error(JSON.stringify(body));
                        this.log.error(resp.statusCode.toString());
                        this.log.error(err.stack);
                        this.restart();
                    }
                }
            );
        });
    }
    generateSecurPin(challenge) {
        return new Promise((resolve, reject) => {
            if (!this.config.pin) {
                this.log.error("Please Enter your S-Pin in the Instance Options");
                reject();
                return;
            }
            const pin = this.toByteArray(this.config.pin);

            const byteChallenge = this.toByteArray(challenge);
            const webcrypto = new Crypto();
            const concat = new Int8Array(pin.concat(byteChallenge));
            webcrypto.subtle
                .digest("SHA-512", concat)
                .then((digest) => {
                    const utf8Array = new Int8Array(digest);
                    resolve(this.toHexString(utf8Array));
                })
                .catch((error) => {
                    this.log.error(error);
                });
        });
    }
    getCodeChallenge() {
        let hash = "";
        let result = "";
        while (hash === "" || hash.indexOf("+") !== -1 || hash.indexOf("/") !== -1 || hash.indexOf("=") !== -1 || result.indexOf("+") !== -1 || result.indexOf("/") !== -1) {
            const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            result = "";
            for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
            result = Buffer.from(result).toString("base64");
            result = result.replace(/=/g, "");
            hash = crypto.createHash("sha256").update(result).digest("base64");
            hash = hash.slice(0, hash.length - 1);
        }
        return [result, hash];
    }
    getNonce() {
        const timestamp = Date.now();
        let hash = crypto.createHash("sha256").update(timestamp.toString()).digest("base64");
        hash = hash.slice(0, hash.length - 1);
        return hash;
    }
    toHexString(byteArray) {
        return Array.prototype.map
            .call(byteArray, function (byte) {
                return ("0" + (byte & 0xff).toString(16).toUpperCase()).slice(-2);
            })
            .join("");
    }

    toByteArray(hexString) {
        const result = [];
        for (let i = 0; i < hexString.length; i += 2) {
            result.push(parseInt(hexString.substr(i, 2), 16));
        }
        return result;
    }
    stringIsAValidUrl(s) {
        try {
            new URL(s);
            return true;
        } catch (err) {
            return false;
        }
    }
    randomString(length) {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    toCammelCase(string) {
        return string.replace(/-([a-z])/g, function (g) {
            return g[1].toUpperCase();
        });
    }
    extractHidden(body) {
        const returnObject = {};
        let matches;
        if (body.matchAll) {
            matches = body.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g);
        } else {
            this.log.warn("The adapter needs in the future NodeJS v12. https://forum.iobroker.net/topic/22867/how-to-node-js-f%C3%BCr-iobroker-richtig-updaten");
            matches = this.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g, body);
        }
        for (const match of matches) {
            returnObject[match[1]] = match[2];
        }
        return returnObject;
    }
    matchAll(re, str) {
        let match;
        const matches = [];

        while ((match = re.exec(str))) {
            // add all matched groups
            matches.push(match);
        }

        return matches;
    }
    getIdStatus(vin) {
        return new Promise(async (resolve, reject) => {

          
         
    
          await axios({
            method: "get",
            url: "https://emea.bff.cariad.digital/vehicle/v1/vehicles/" + vin + "/selectivestatus?jobs=access,activeVentilation,auxiliaryHeating,batteryChargingCare,batterySupport,charging,chargingProfiles,climatisation,climatisationTimers,departureProfiles,fuelStatus,honkAndFlash,hybridCarAuxiliaryHeating,userCapabilities,vehicleHealthWarnings,vehicleHealthInspection,vehicleLights,measurements,departureTimers",
            headers: {
              "content-type": "application/json",
              accept: "*/*",
              authorization: "Bearer " + this.config.atoken,
              "accept-language": "de-DE,de;q=0.9",
              "user-agent": this.userAgent,
              "content-version": "1",
            },
          })
            .then(async (res) => {
              this.log.debug(JSON.stringify(res.data));
              const data = {};
              for (const key in res.data) {
                if (key === "userCapabilities") {
                  data[key] = res.data[key];
                } else {
                  for (const subkey in res.data[key]) {
                    data[subkey] = res.data[key][subkey].value || {};
                  }
                }
              }
              if (data.odometerStatus && data.odometerStatus.error) {
                this.log.warn("Odometer Error: " + data.odometerStatus.error);
                this.log.info(
                  "Please activate die Standortdaten freigeben und die automatische Terminvereinbarung in der VW App to receive odometer data",
                );
              }
              var batteryData = this.extractKeys(this, vin + ".status", data);

              await axios({
                method: "get",
                url: "https://emea.bff.cariad.digital/vehicle/v1/vehicles/" + vin + "/parkingposition",
                headers: {
                  "content-type": "application/json",
                  accept: "*/*",
                  authorization: "Bearer " + this.config.atoken,
                  "accept-language": "de-DE,de;q=0.9",
                  "user-agent": this.userAgent,
                  "content-version": "1",
                },
              })
                .then((res) => {
                  if (res.status == 200) {
                    batteryData.state = "parked";
                  } else if (res.status == 204) {
                    batteryData.state = "moving";
                  }
                  this.log.debug(JSON.stringify(res.data));
                  batteryData.position = res.data.data;
                
                })
                .catch((error) => {
                  this.log.debug(error);
                  //   error.response && this.log.error(JSON.stringify(error.response.data));
                });



              resolve(batteryData);
              // this.extractKeys(this, vin + ".status", data);
            /*  this.json2iob.parse(vin + ".status", data, { forceIndex: false });
              if (this.config.rawJson) {
                await this.setObjectNotExistsAsync(vin + ".status" + "rawJson", {
                  type: "state",
                  common: {
                    name: vin + ".status" + "rawJson",
                    role: "state",
                    type: "json",
                    write: false,
                    read: true,
                  },
                  native: {},
                });
                this.setState(vin + ".status" + "rawJson", JSON.stringify(data), true);
              }
              resolve();*/
            })
            .catch((error) => {
              if (error.response && error.response.status >= 500) {
                this.log.info("Server not available:" + JSON.stringify(error.response.data));
                return;
              }
              this.log.error(error);
              error && error.response && this.log.error(JSON.stringify(error.response.data));
              reject();
            });
        });
      }

}

module.exports = (options) => new VWConnector(options);
