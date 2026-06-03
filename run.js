const configloader = require("config");
const TronityConnector = require("./tronityconnector");
const fromTronityFormat = require("./fromTronityFormat");
const { consumeState, initConsumer } = require("./stateconsumer");

const consumerLocation = configloader.get("Hnkr");
initConsumer(consumerLocation);

const creds = configloader.get("Tronity");
const connector = new TronityConnector(creds.clientId, creds.clientSecret);

connector.run().then(tronityData => {
    if (!tronityData) return;
    const state = fromTronityFormat(tronityData);
    consumeState(state);
}).catch(err => {
    console.error("Error:", err.response ? JSON.stringify(err.response.data) : err.message);
    process.exit(1);
});
