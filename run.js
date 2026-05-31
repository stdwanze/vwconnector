const vw = require('./vwconnectloader');
const {consumeState, initConsumer } = require("./stateconsumer");
const configloader = require("config");


const consumerLocation = configloader.get('Hnkr');
initConsumer(consumerLocation);
const connector = vw();
connector.login().then(()=>connector.getIdStatus("WVWZZZED7SE023911").then((status)=>
{
    consumeState(status);
    console.log(status);
}));

