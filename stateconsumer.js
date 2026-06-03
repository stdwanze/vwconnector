const url = ""

var request = require('request');
var options = {
  'method': 'POST',
  'url': url,
  'headers': {
      "Content-Type" : "application/json"
  },
  body: null

};

function initConsumer(conf){
    options.url = conf.location;
}
function consumeState(state){

    state.time = new Date(state.chargingstatus.carCapturedTimestamp).getTime();
    console.log("consumeState: chargingstatus.chargingState =", state.chargingstatus.chargingState);
    console.log("consumeState: state.state =", state.state);

    if(state.state == "parked" && state.chargingstatus.chargingState == "charging") {
        console.log("consumeState: overriding state -> charging");
        state.state = "charging";
    } else {
        console.log("consumeState: state unchanged");
    }

    console.log("consumeState: posting to", options.url);
    options.body = JSON.stringify(state);

    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log("consumeState: response:", response.body);
    });
}

module.exports = {
  initConsumer,   consumeState
}