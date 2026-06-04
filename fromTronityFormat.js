function fromTronityFormat(t) {
    const ts = new Date(t.timestamp || Date.now()).toISOString().replace(/\.\d+Z$/, "Z");

    const plugConnected = t.plugged === true;
    const chargingVal = t.charging ? t.charging.toLowerCase() : "";
    const isCharging = chargingVal === "charging" || chargingVal === "ac" || chargingVal === "dc";
    const chargeType = chargingVal === "dc" ? "dc" : "ac";
    const chargingState = isCharging ? "charging" : (plugConnected ? "readyForCharging" : "notReadyForCharging");

    const chargingstatus = {
        carCapturedTimestamp: ts,
        remainingChargingTimeToComplete_min: t.chargeRemainingTime != null ? t.chargeRemainingTime : 0,
        chargingState: chargingState,
        chargeMode: "manual",
        chargePower_kW: t.chargerPower != null ? t.chargerPower : 0,
        chargeRate_kmph: 0,
        chargeType: chargeType,
        chargingSettings: "default",
        chargingScenario: isCharging ? "immediatelyChargingActive" : "notCharging",
    };

    const batterystatus = {
        carCapturedTimestamp: ts,
        currentSOC_pct: t.level != null ? t.level : 0,
        cruisingRangeElectric_km: t.range != null ? t.range : 0,
    };

    const plugstatus = {
        carCapturedTimestamp: ts,
        plugConnectionState: plugConnected ? "connected" : "disconnected",
        plugLockState: plugConnected ? "locked" : "unlocked",
        externalPower: isCharging ? "active" : "unavailable",
        ledColor: isCharging ? "green" : "none",
    };

    const position = (t.latitude != null && t.longitude != null)
        ? { lat: t.latitude, lon: t.longitude, carCapturedTimestamp: ts }
        : null;

    var result = {
        chargingstatus: chargingstatus,
        batterystatus: batterystatus,
        plugstatus: plugstatus,
        element: {
            accessStatus: {
                overallStatus: t.status != null ? t.status : "safe",
                carCapturedTimestamp: ts,
            },
            batteryStatus: batterystatus,
            chargingStatus: chargingstatus,
            plugStatus: plugstatus,
            odometerStatus: {
                carCapturedTimestamp: ts,
                odometer: t.odometer != null ? t.odometer : 0,
            },
            rangeStatus: {
                carCapturedTimestamp: ts,
                electricRange: t.range != null ? t.range : 0,
                totalRange_km: t.range != null ? t.range : 0,
            },
            fuelLevelStatus: {
                carCapturedTimestamp: ts,
                currentSOC_pct: t.level != null ? t.level : 0,
                primaryEngineType: "electric",
                carType: "electric",
            },
            maintenanceStatus: {
                carCapturedTimestamp: ts,
                mileage_km: t.odometer != null ? t.odometer : 0,
            },
            temperatureBatteryStatus: {
                carCapturedTimestamp: ts,
                temperatureHvBatteryMin_K: "273.15",
                temperatureHvBatteryMax_K: "273.15",
            },
        },
        time: t.timestamp != null ? t.timestamp : Date.now(),
        whenhappend: ts,
    };

    result.state = (position || isCharging) ? "parked" : "moving";
    if (position) result.position = position;

    return result;
}

module.exports = fromTronityFormat;
