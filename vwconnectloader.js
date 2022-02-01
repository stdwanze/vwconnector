
const request = require("request");
const crypto = require("crypto");
const { Crypto } = require("@peculiar/webcrypto");
const { v4: uuidv4 } = require("uuid");
const traverse = require("traverse");
const { extractKeys } = require("./lib/extractKeys");
const configloader = require('config');
const { savetokens, loadtokens} = require('./lib/tokenholder');
class VWConnector {

    constructor(options){

        this.configLoaded =  configloader.get('VW.creds');
        this.log = { error: function(msg){ console.log("error:" +msg);}, warn: function (msg) {console.log("WARN:"+msg);},debug: function (msg){ /*console.log("debug:" +msg)*/;}, info: function(msg){console.log("info:" +msg);} };
        this.type = "Id";
        this.country = "DE";
        this.clientId = "a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com";
        this.xclientId = "";
        this.scope = "openid profile badge cars dealers birthdate vin";
        this.redirect = "weconnect://authenticated";
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
        return {
            chargingstatus,batterystatus,plugstatus,climatestatus
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

            const [code_verifier, codeChallenge] = this.getCodeChallenge();

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
            if (this.config.type === "vw" || this.config.type === "vwv2" || this.config.type === "go") {
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
                    url = "https://login.apps.emea.vwapps.io/authorize?nonce=" + this.randomString(16) + "&redirect_uri=weconnect://authenticated";
                }
            }
            const loginRequest = request(
                {
                    method: method,
                    url: url,
                    headers: {
                        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
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
                            if (err && err.message === "Invalid protocol: wecharge:") {
                                this.log.debug("Found WeCharge connection");
                                this.getTokens(loginRequest, code_verifier, reject, resolve);
                            } else {
                                this.log.debug("No WeCharge found, cancel login");
                                resolve();
                            }
                            return;
                        }
                        if (err && err.message.indexOf("Invalid protocol:") !== -1) {
                            this.log.debug("Found Token");
                            this.getTokens(loginRequest, code_verifier, reject, resolve);
                            return;
                        }
                        this.log.error("Failed in first login step ");
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        err && err.message && this.log.error(err.message);
                        loginRequest && loginRequest.uri && loginRequest.uri.query && this.log.debug(loginRequest.uri.query.toString());

                        reject();
                        return;
                    }

                    try {
                        let form = {};
                        if (body.indexOf("emailPasswordForm") !== -1) {
                            this.log.debug("parseEmailForm");
                            form = this.extractHidden(body);
                            form["email"] = this.config.user;
                        } else {
                            this.log.error("No Login Form found for type: " + this.type);
                            this.log.debug(JSON.stringify(body));
                            reject();
                            return;
                        }
                        request.post(
                            {
                                url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/identifier",
                                headers: {
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                    "Accept-Language": "en-US,en;q=0.9",
                                    "Accept-Encoding": "gzip, deflate",
                                    "x-requested-with": this.xrequest,
                                },
                                form: form,
                                jar: this.jar,
                                gzip: true,
                                followAllRedirects: true,
                            },
                            (err, resp, body) => {
                                if (err || (resp && resp.statusCode >= 400)) {
                                    this.log.error("Failed to get login identifier");
                                    err && this.log.error(err);
                                    resp && this.log.error(resp.statusCode.toString());
                                    body && this.log.error(JSON.stringify(body));
                                    reject();
                                    return;
                                }
                                try {
                                    if (body.indexOf("emailPasswordForm") !== -1) {
                                        this.log.debug("emailPasswordForm2");

                                        /*
                                        const stringJson =body.split("window._IDK = ")[1].split(";")[0].replace(/\n/g, "")
                                        const json =stringJson.replace(/(['"])?([a-z0-9A-Z_]+)(['"])?:/g, '"$2": ').replace(/'/g, '"')
                                        const jsonObj = JSON.parse(json);
                                        */
                                        form = {
                                            _csrf: body.split("csrf_token: '")[1].split("'")[0],
                                            email: this.config.user,
                                            password: this.config.password,
                                            hmac: body.split('"hmac":"')[1].split('"')[0],
                                            relayState: body.split('"relayState":"')[1].split('"')[0],
                                        };} else {
                                        this.log.error("No Login Form found. Please check your E-Mail in the app.");
                                        this.log.debug(JSON.stringify(body));
                                        reject();
                                        return;
                                    }
                                    request.post(
                                        {
                                            url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/authenticate",
                                            headers: {
                                                "Content-Type": "application/x-www-form-urlencoded",
                                                "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                "Accept-Language": "en-US,en;q=0.9",
                                                "Accept-Encoding": "gzip, deflate",
                                                "x-requested-with": this.xrequest,
                                            },
                                            form: form,
                                            jar: this.jar,
                                            gzip: true,
                                            followAllRedirects: false,
                                        },
                                        (err, resp, body) => {
                                            if (err || (resp && resp.statusCode >= 400)) {
                                                this.log.error("Failed to get login authenticate");
                                                err && this.log.error(err);
                                                resp && this.log.error(resp.statusCode.toString());
                                                body && this.log.error(JSON.stringify(body));
                                                reject();
                                                return;
                                            }

                                            try {
                                                this.log.debug(JSON.stringify(body));
                                                this.log.debug(JSON.stringify(resp.headers));

                                                if (resp.headers.location.split("&").length <= 2 || resp.headers.location.indexOf("/terms-and-conditions?") !== -1) {
                                                    this.log.warn(resp.headers.location);
                                                    this.log.warn("No valid userid, please visit this link or logout and login in your app account:");
                                                    this.log.warn("https://" + resp.request.host + resp.headers.location);
                                                    this.log.warn("Try to auto accept new consent");

                                                    request.get(
                                                        {
                                                            url: "https://" + resp.request.host + resp.headers.location,
                                                            jar: this.jar,
                                                            headers: {
                                                                "User-Agent":
                                                                    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                "Accept-Language": "en-US,en;q=0.9",
                                                                "Accept-Encoding": "gzip, deflate",
                                                                "x-requested-with": this.xrequest,
                                                            },
                                                            followAllRedirects: true,
                                                            gzip: true,
                                                        },
                                                        (err, resp, body) => {
                                                            this.log.debug(body);

                                                            const form = this.extractHidden(body);
                                                            const url = "https://" + resp.request.host + resp.req.path.split("?")[0];
                                                            this.log.debug(JSON.stringify(form));
                                                            request.post(
                                                                {
                                                                    url: url,
                                                                    jar: this.jar,
                                                                    headers: {
                                                                        "Content-Type": "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                        "Accept-Language": "en-US,en;q=0.9",
                                                                        "Accept-Encoding": "gzip, deflate",
                                                                        "x-requested-with": this.xrequest,
                                                                    },
                                                                    form: form,
                                                                    followAllRedirects: true,
                                                                    gzip: true,
                                                                },
                                                                (err, resp, body) => {
                                                                    if ((err && err.message.indexOf("Invalid protocol:") !== -1) || (resp && resp.statusCode >= 400)) {
                                                                        this.log.warn("Failed to auto accept");
                                                                        err && this.log.error(err);
                                                                        resp && this.log.error(resp.statusCode.toString());
                                                                        body && this.log.error(JSON.stringify(body));
                                                                        reject();
                                                                        return;
                                                                    }
                                                                    this.log.info("Auto accept succesful. Restart adapter in 10sec");
                                                                    setTimeout(() => {
                                                                        this.restart();
                                                                    }, 10 * 1000);
                                                                }
                                                            );
                                                        }
                                                    );

                                                    reject();
                                                    return;
                                                }
                                                this.config.userid = resp.headers.location.split("&")[2].split("=")[1];
                                                if (!this.stringIsAValidUrl(resp.headers.location)) {
                                                    if (resp.headers.location.indexOf("&error=") !== -1) {
                                                        const location = resp.headers.location;
                                                        this.log.error("Error: " + location.substring(location.indexOf("error="), location.length - 1));
                                                    } else {
                                                        this.log.error("No valid login url, please download the log and visit:");
                                                        this.log.error("http://" + resp.request.host + resp.headers.location);
                                                    }
                                                    reject();
                                                    return;
                                                }

                                                let getRequest = request.get(
                                                    {
                                                        url: resp.headers.location || "",
                                                        headers: {
                                                            "User-Agent":
                                                                "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                            "Accept-Language": "en-US,en;q=0.9",
                                                            "Accept-Encoding": "gzip, deflate",
                                                            "x-requested-with": this.xrequest,
                                                        },
                                                        jar: this.jar,
                                                        gzip: true,
                                                        followAllRedirects: true,
                                                    },
                                                    (err, resp, body) => {
                                                        if (err) {
                                                            this.log.debug(err);
                                                            this.getTokens(getRequest, code_verifier, reject, resolve);
                                                        } else {
                                                            this.log.debug("No Token received visiting url and accept the permissions.");
                                                            const form = this.extractHidden(body);
                                                            getRequest = request.post(
                                                                {
                                                                    url: getRequest.uri.href,
                                                                    headers: {
                                                                        "Content-Type": "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                        "Accept-Language": "en-US,en;q=0.9",
                                                                        "Accept-Encoding": "gzip, deflate",
                                                                        "x-requested-with": this.xrequest,
                                                                        referer: getRequest.uri.href,
                                                                    },
                                                                    form: form,
                                                                    jar: this.jar,
                                                                    gzip: true,
                                                                    followAllRedirects: true,
                                                                },
                                                                (err, resp, body) => {
                                                                    if (err) {
                                                                        this.getTokens(getRequest, code_verifier, reject, resolve);
                                                                    } else {
                                                                        this.log.error("No Token received.");
                                                                        try {
                                                                            this.log.debug(JSON.stringify(body));
                                                                        } catch (err) {
                                                                            this.log.error(err);
                                                                            reject();
                                                                        }
                                                                    }
                                                                }
                                                            );
                                                        }
                                                    }
                                                );
                                            } catch (err2) {
                                                this.log.error("Login was not successful, please check your login credentials and selected type");
                                                err && this.log.error(err);
                                                this.log.error(err2);
                                                this.log.error(err2.stack);
                                                reject();
                                            }
                                        }
                                    );
                                } catch (err) {
                                    this.log.error(err);
                                    reject();
                                }
                            }
                        );
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    receiveLoginUrl() {
        return new Promise((resolve, reject) => {
            request(
                {
                    method: "GET",
                    url: "https://login.apps.emea.vwapps.io/authorize?nonce=" + this.randomString(16) + "&redirect_uri=weconnect://authenticated",
                    headers: {
                        Host: "login.apps.emea.vwapps.io",
                        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
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
                }
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
            // "user-agent": "okhttp/3.7.0",
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
        if (this.config.type === "id") {
            url = "https://login.apps.emea.vwapps.io/login/v1";
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
                "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                "accept-language": "de-de",
            };
            if (this.type === "Wc") {
                method = "GET";
                url = "https://wecharge.apps.emea.vwapps.io/user-identity/v1/identity/login?redirect_uri=wecharge://authenticated&code=" + jwtauth_code;
                redirerctUri = "wecharge://authenticated";
                headers["x-api-key"] = "yabajourasW9N8sm+9F/oP==";
            }
        }
        if (this.config.type === "audi") {
            this.getVWToken({}, jwtid_token, reject, resolve);
            return;
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
            }
        );
    }

    getVWToken(tokens, jwtid_token, reject, resolve) {
        if (this.config.type !== "audi") {
            if (this.config.type === "id") {
                if (this.type === "Wc") {
                    this.config.wc_access_token = tokens.wc_access_token;
                    this.config.wc_refresh_token = tokens.refresh_token;
                    this.log.debug("Wallcharging login successfull");
                   // this.getWcData(100);
                    resolve();
                    return;
                }
                this.config.atoken = tokens.accessToken;
                this.config.rtoken = tokens.refreshToken;
                savetokens(tokens.accessToken,tokens.refreshToken);
                //configure for wallcharging login

/*                this.refreshTokenInterval = setInterval(() => {
                    this.refreshIDToken().catch(() => {});
                }, 0.9 * 60 * 60 * 1000); // 0.9hours
*/
                //this.config.type === "wc"
                this.type = "Wc";
                this.country = "DE";
                this.clientId = "0fa5ae01-ebc0-4901-a2aa-4dd60572ea0e@apps_vw-dilab_com";
                this.xclientId = "";
                this.scope = "openid profile address email";
                this.redirect = "wecharge://authenticated";
                this.xrequest = "com.volkswagen.weconnect";
                this.responseType = "code id_token token";
                this.xappversion = "";
                this.xappname = "";
                this.login().catch(() => {
                    this.log.warn("Failled wall charger login");
                });
                resolve();
                return;
            }

            this.config.atoken = tokens.access_token;
            this.config.rtoken = tokens.refresh_token;
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken().catch(() => {
                    this.log.error("Refresh Token was not successful");
                });
            }, 0.9 * 60 * 60 * 1000); // 0.9hours
        }
        if (this.config.type === "go" || this.config.type === "id" || this.config.type === "skodae") {
            resolve();
            return;
        }
        request.post(
            {
                url: "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token",
                headers: {
                    "User-Agent": "okhttp/3.7.0",
                    "X-App-Version": this.xappversion,
                    "X-App-Name": this.xappname,
                    "X-Client-Id": this.xclientId,
                    Host: "mbboauth-1d.prd.ece.vwg-connect.com",
                },
                form: {
                    grant_type: "id_token",
                    token: jwtid_token,
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
            }
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
        return new Promise((resolve, reject) => {
            request.get(
                {
                    url: "https://mobileapi.apps.emea.vwapps.io/vehicles/" + vin + "/status",

                    headers: {
                        accept: "*/*",
                        "content-type": "application/json",
                        "content-version": "1",
                        "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                        "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                        "accept-language": "de-de",
                        authorization: "Bearer " + this.config.atoken,
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());

                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));
                    try {
                        var batteryData = this.extractKeys(this, vin + ".status", body.data);
                        resolve(batteryData);
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }

}

module.exports = (options) => new VWConnector(options);