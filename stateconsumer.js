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
    state.state = state.chargingstatus.chargingState == "readyForCharging" ? "parked" : "charging";
    options.body = JSON.stringify(state);

    request(options, function (error, response) {
    if (error) throw new Error(error);
    console.log(response.body);
    });
}

module.exports = {
  initConsumer,   consumeState
}