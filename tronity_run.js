const configloader = require("config");
const TronityConnector = require("./tronityconnector");

const creds = configloader.get("Tronity");
const connector = new TronityConnector(creds.clientId, creds.clientSecret);

connector.run().catch(err => {
    console.error("Error:", err.response ? JSON.stringify(err.response.data) : err.message);
    process.exit(1);
});
