const configloader = require("config");
const EuConnector = require("./euconnector");

const creds = configloader.get("EU");
const vin = creds.vin || null; // optional: target specific VIN

const connector = new EuConnector(creds.email, creds.password, undefined, undefined, undefined, creds.extraIdentifiers || []);

connector.run(vin).then(data => {
    if (!data) return;
    const result = EuConnector.toTronityFormat(data);
    console.log(JSON.stringify(result, null, 2));
}).catch(err => {
    console.error("Error:", err.message);
    process.exit(1);
});
