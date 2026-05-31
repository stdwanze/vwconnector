const axios = require("axios").default;

const TARGET_VEHICLE_ID = "6a184eded3829b00018f512d";
const BASE_URL = "https://api.tronity.tech/tronity";
const AUTH_URL = "https://api.tronity.tech/authentication";

class TronityConnector {
    constructor(clientId, clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.accessToken = null;
    }

    async authenticate() {
        try {
            const response = await axios.post(AUTH_URL, {
                client_id: this.clientId,
                client_secret: this.clientSecret,
                grant_type: "app",
            }, {
                headers: { "Content-Type": "application/json" },
            });
            this.accessToken = response.data.access_token;
            console.log("Tronity: authenticated");
        } catch (err) {
            const msg = err.response ? JSON.stringify(err.response.data) : err.message;
            throw new Error("Tronity authentication failed: " + msg);
        }
    }

    async getVehicles() {
        const response = await axios.get(`${BASE_URL}/vehicles`, {
            headers: { Authorization: `Bearer ${this.accessToken}` },
        });
        return response.data.data || response.data;
    }

    async getLastRecord(vehicleId) {
        const response = await axios.get(`${BASE_URL}/vehicles/${vehicleId}/last_record`, {
            headers: { Authorization: `Bearer ${this.accessToken}` },
        });
        return response.data;
    }

    async run() {
        await this.authenticate();

        const vehicles = await this.getVehicles();
        console.log(`Found ${vehicles.length} vehicle(s):`);
        vehicles.forEach(v => console.log(`  - ${v.id} (${v.display_name || v.name || "unknown"})`));

        const found = vehicles.find(v => v.id === TARGET_VEHICLE_ID);
        if (!found) {
            console.error(`Vehicle ${TARGET_VEHICLE_ID} not found in account`);
            return null;
        }

        console.log(`\nVehicle ${TARGET_VEHICLE_ID} found. Fetching last record...`);
        const record = await this.getLastRecord(TARGET_VEHICLE_ID);
        console.log("Last record:", JSON.stringify(record, null, 2));
        return record;
    }
}

module.exports = TronityConnector;
