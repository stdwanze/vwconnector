const configloader = require("config");
const EuConnector = require("./euconnector");

const creds = configloader.get("EU");
const vin = creds.vin || null; // optional: target specific VIN

const connector = new EuConnector(creds.email, creds.password);

connector.run(vin).catch(err => {
    console.error("Error:", err.message);
    process.exit(1);
});
