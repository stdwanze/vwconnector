
const fs = require('fs');

function savetokens(atoken, refreshtoken)
{
    fs.writeFileSync('tokens', atoken+ "###"+ refreshtoken+ "###"+ new Date().getTime());
}

function loadtokens()
{

    try{

        const data = fs.readFileSync('tokens');
        if(data != null && data.length> 0){
            var parts = data.toString().split("###");
            if(parts.length == 3){

                const now = new Date();
                const tokenTime = new Date(parseInt(parts[2]));
                const minutesSpan =  ( now.getTime() - tokenTime.getTime() ) / (1000 *60);
                if(minutesSpan > 50){
                    return null;
                }

                return {
                    atoken : parts[0],
                    refreshtoken : parts[1]
                }
            }
        }
    }
    catch(ex){
        return null;
    }

    return null;
}

module.exports = {
    savetokens,
    loadtokens
}
