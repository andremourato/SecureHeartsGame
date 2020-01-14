var colors = require('colors')

function handleInvalidSignatureError(client,player_id){
    console.log(colors.yellow('Closing connection to player ')+colors.red(player_id)+colors.yellow(' for invalid signature or certificate'))
    client.emit('end',{error:'INVALID_SIGNATURE'})
}

function handleInvalidAcceptedPlayerList(client,player_id){
    console.log(colors.yellow('Wrong accepted player list. Closing connection with player ')+colors.red(player_id))
    client.emit('end',{error:'INVALID_ACCEPTED_PLAYER_LIST'})
}

async function handleUserAlreadyExists(client,player_id,RSA_PASSWORD,rsa_key_pair,rsa_sign){
    var payload = {status:'error',error:`USER ${player_id} ALREADY EXISTS`}
    var serverSignature = await rsa_sign(RSA_PASSWORD,rsa_key_pair.privateKey,JSON.stringify(payload))
    client.write(Buffer.from(JSON.stringify({msg:payload,signature: serverSignature.signature})))
    console.log(colors.yellow('The username '+colors.red(player_id)+' is already taken. Closing connection.'))
    client.emit('end',{error:'USER_ALREADY_EXISTS'})
}

module.exports = {
    handleInvalidSignatureError,
    handleInvalidAcceptedPlayerList,
    handleUserAlreadyExists,
};