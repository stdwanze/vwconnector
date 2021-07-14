const vw = require('./vwconnectloader');
const {consumeState, initConsumer } = require("./stateconsumer");
const configloader = require("config");


const consumerLocation = configloader.get('Hnkr');
initConsumer(consumerLocation);
const connector = vw();
connector.login().then(()=>connector.getIdStatus("WVWZZZE1ZMP041117").then((status)=>
{
    consumeState(status);
    console.log(status);
}));

