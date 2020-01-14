var net = require('net')
var colors = require('colors')
var fs = require('fs')
const {Worker} = require('worker_threads')
var {rsa_generate_key_pair,
    rsa_decrypt,
    rsa_encrypt,
    sym_decrypt,
    sym_encrypt,
    rsa_sign,
    encodeBase64,
    decodeBase64,
    rsa_verify_signed_certificate,
    rsa_verify_chain_of_trust,
    rsa_verify,
    hash_sha256,
} = require('./security_interface')

var {handleInvalidSignatureError,
    handleInvalidAcceptedPlayerList,
    handleUserAlreadyExists
} = require('./error_handlers')

const PORT = 3000
const IP_ADDRESS = '127.0.0.1'

var player_list = [] //current connections
var game_list = [] //the list of ongoing game tables (threads)

//security attributes
var RSA_PASSWORD = '12345678' //TODO: Change to more secure password
var rsa_key_pair = null

//////////// COMMUNICATION FUNCTIONS ////////////
async function sendSigned(client,payload){
    var serverSignature = await rsa_sign(RSA_PASSWORD,rsa_key_pair.privateKey,JSON.stringify(payload))
    client.write(Buffer.from(JSON.stringify({msg:payload,signature: serverSignature.signature})))
}

var server = net.createServer(async (client) => {
    console.log(colors.blue('A player has been connected | Number of connected players:'+player_list.length))
    client.on('end', () => {
        var player = getPlayerFromClient(client)
        if(player){
            var currently_connected_game = getGameFromPlayer(player)
            //disconnects the player from the game if he is connected to any
            if(currently_connected_game != -1){
                stopGame(getGameFromPlayer(player))
            }
            removePlayer(client)
                console.log(colors.blue('Player ')+ colors.red(player.id)+colors.blue(' has been disconnected | Number of connected players:'+player_list.length))
        }
    });

    client.on('close', (e) => {
        // console.log(e)
    })

    client.on('data',async (data)=>{
        var args = data.toString().split(':')
        var signature = args[args.length-1]
        var payload = args.slice(0,args.length-1).join(':')
        var player = null
        var validSignature = false
        var validUsername = true
        if(args[0] == 'CITIZEN_CARD_AUTHENTICATION'){
            if(playerExists(args[1])){
                validUsername = false
            }else{
                validSignature = authenticateCitizenCard(client,args[1],args[2])
                player = getPlayerFromClient(client)
            }
        }else{
            if(args[0] == 'LOG_IN'){
                if(playerExists(args[1])){
                    validUsername = false
                }else{
                    logIn(client,args[1],args[2])
                }
            }
            if(validUsername){
                player = getPlayerFromClient(client)
                if(args[0] == 'CLIENT_BIT_COMMITMENT' || args[0] == 'ACCEPTED_PLAYERS' ||
                args[0] == 'CITIZEN_CARD_AUTHENTICATION' || args[0] == 'LOG_IN' || args[0] == 'PLAY_CARD' ||
                args[0] == 'CHEATING_VERIFICATION' || args[0] == 'SIGNED_RECEIPT'){
                    var verify = await rsa_verify(player.publicKey,signature,payload)
                    validSignature = verify.valid
                }else { //Only verifies the necessary operations, else it doesn't need to
                    validSignature = true
                }
            }
        }
        if(!validUsername){
            handleUserAlreadyExists(client,args[1],RSA_PASSWORD,rsa_key_pair,rsa_sign)
        } else if(!validSignature){
            handleInvalidSignatureError(client,player.id)
        } else {
            switch(args[0]){
                case 'CHEATING_VERIFICATION_START':
                    startCheatingVerification(client)
                    break
                case 'CHEATING_VERIFICATION':
                    verifyCheating(client,args.slice(1,4))
                    break
                case 'CHEATING_TURNING_IN_HAND':
                    handleCheating(client,args[1],args.slice(2,args.length))
                    break
                case 'SIGNED_RECEIPT':
                    handleSignedReceipt(client,args[1])
                    break
                case 'CLIENT_REVEAL_STAGE':
                    handleRevealStage(client,args[1])
                    break
                case 'CLIENT_BIT_COMMITMENT':
                    handleBitCommitment(client,args[1],args[2])
                    break
                case 'CLIENT_DISTRIBUTION_FINISHED':
                    handleDeckDistributionFinished(client)
                    break
                case 'CLIENT_DISTRIBUTE_DECK':
                    distributeDeck(client)
                    break
                case 'RETURN_DECK':
                    returnDeck(client,args.slice(1,args.length))
                    break
                case 'ESTABLISH_SECURE_CHANNEL':
                    establishSecureChannel(client,getClientFromPlayerID(args[1]),args[2])
                    break
                case 'DISTRIBUTE_SECURE_CHANNEL_SYM_KEYS':
                    distributeSecureChannelKeys(client)
                    break
                case 'SECURE_CHANNEL':
                    var msg = null
                    if(args.length == 3)
                        msg = args[2]
                    else
                        msg = args.slice(2,args.length)
                    communicateSecureChannel(client,getClientFromPlayerID(args[1]),msg)
                    break
                case 'GAME_PLAYERS_AUTHENTICATION':
                    handleGamePlayersAuthentication(client)
                    break
                case 'ACCEPTED_PLAYERS':
                    handleAcceptedPlayers(client,args.slice(1,args.length-1))
                    break
                case 'LEAVE_LOBBY':
                    disconnectFromGame(client)
                    break
                case 'WAITING_IN_LOBBY':
                    waitingInLobby(client)
                    break
                case 'PLAY_GAME':
                    playGame(client)
                    break
                case 'CREATE_GAME':
                    createGame(player)
                    break
                case 'JOIN_GAME':
                    joinGame(client,args[1])
                    break
                case 'LIST_GAME_HISTORY':
                    listGameHistory(client)
                    break
                case 'LIST_PLAYERS':
                    listPlayers(client)
                    break
                case 'LIST_GAMES':
                    listGames(client)
                    break
                case 'get_state':
                    getState(client)
                    break
                case 'PLAY_CARD':
                    playCard(client,args[1],args[2])
                    break
            }
        }
    })
});

function playerExists(player_id){
    return getClientFromPlayerID(player_id) != -1
}

///////////////////////////////////////////////
////////////PROCESS FUNCTIONS//////////////////
///////////////////////////////////////////////

async function startCheatingVerification(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    //Checks if it was sent with a valid signature
    game.num_ready += 1
    if(game.num_ready == 4){
        game.num_ready = 0
        var plClient = getClientFromPlayerID(game.players[0].id)
        var player = getPlayerFromClient(plClient)
        sendSigned(plClient,{status:'SEND_CHEATING_STATUS'})
    }
}

function verifyCheating(client,cheatingParameters){
    var cheatingPlayer = getPlayerFromClient(getClientFromPlayerID(cheatingParameters[1]))
    var card = cheatingParameters[2]
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    // console.log('player:',player.id,' cheatingparams:',cheatingParameters)
    if(cheatingParameters[0] == 'PLAYED_MY_CARD'){
        game.state = 'PLAYERS_TURNING_IN_HANDS'
        game.num_ready = 0
        game.cheating_info = {
            accuser: player.id,
            accused: cheatingPlayer.id,
            card,
            info: 'PLAYED_MY_CARD'
        }
        broadcastMessageToGamePlayers(game,{status:'CHEATING_TURN_OVER_HAND'})
    }else if(cheatingParameters[0] == 'PLAYED_CARD_TWICE'){
        game.state = 'PLAYERS_TURNING_IN_HANDS'
        game.num_ready = 0
        game.cheating_info = {
            accuser: player.id,
            accused: cheatingPlayer.id,
            card,
            info: 'PLAYED_CARD_TWICE'
        }
        broadcastMessageToGamePlayers(game,{status:'CHEATING_TURN_OVER_HAND'})
        game.worker.postMessage({
            process: 'check_played_twice',
            accuser: player.id,
            accused: cheatingPlayer.id,
            card,
        })
    }else if(cheatingParameters[0] == 'RENOUNCE'){
        game.state = 'PLAYERS_TURNING_IN_HANDS'
        game.num_ready = 0
        game.cheating_info = {
            accuser: player.id,
            accused: cheatingPlayer.id,
            card,
            info: 'RENOUNCE'
        }
        broadcastMessageToGamePlayers(game,{status:'CHEATING_TURN_OVER_HAND'})
        game.worker.postMessage({
            process: 'check_renounce',
            accuser: player.id,
            accused: cheatingPlayer.id,
            card,
        })
    }else{
        game.num_ready += 1
        if(game.num_ready == 4){
            game.num_ready = 0
            broadcastMessageToGamePlayers(game,{status:'NO_CHEATING'})
        }else{
            sendSigned(getClientFromPlayerID(game.players[game.num_ready].id),{status:'SEND_CHEATING_STATUS'})
        }
    }
}

//Find out whose fault is it. R2 is a 128 bit sequence and C is the list of encrypted cards
async function handleCheating(client,R2,C){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    if(player != -1 && game != -1 && game.cheating_info.info == 'PLAYED_MY_CARD'){
        var r = await hash_sha256(player.R1,R2,C)
        var {accuser, accused, card} = game.cheating_info
        //Only check the hand of the accuser and the accused. One of them is right and the other is wrong since it can be a false accusation o
        if(player.id == accused){
            //If the bit commitment is the same it means that the player provided the right bit commitment. Time to check if he has the card
            if(r.hash == player.bitCommitment){
                //Sorts the player list in the inverse order to decrypt the cards that the player has
                var sortedPlayers = [...game.players].sort((x,y) => { return y.id.localeCompare(x.id) })
                // console.log('players sort',sortedPlayers)
                var initialHand = []
                for(var j in C){
                    //For player 4
                    var plr1 = sortedPlayers[0]
                    var key1 = plr1.cardEncryptionKey
                    // console.log('card',C[j],'key of',plr1.id,'| key',key1)
                    var result = await sym_decrypt(key1,C[j],game.symmetricEncryptionSettings.algorithm,game.symmetricEncryptionSettings.mode)
                    C[j] = result.cleartext
                    // console.log('card',C[j],'key of',plr1.id,'| result',result)
                    // console.log('done card',C[j],'key of',plr1.id)
                    //For player 3
                    var plr2 = sortedPlayers[1]
                    var key2 = plr2.cardEncryptionKey
                    // console.log('card',C[j],'key of',plr2.id,'| key',key2)
                    var result = await sym_decrypt(key2,C[j],game.symmetricEncryptionSettings.algorithm,game.symmetricEncryptionSettings.mode)
                    C[j] = result.cleartext
                    // console.log('done card',C[j],'key of',plr2.id)
                    //For player 2
                    var plr3 = sortedPlayers[2]
                    var key3 = plr3.cardEncryptionKey
                    // console.log('card',C[j],'key of',plr3.id,'| key',key3)
                    var result = await sym_decrypt(key3,C[j],game.symmetricEncryptionSettings.algorithm,game.symmetricEncryptionSettings.mode)
                    C[j] = result.cleartext
                    // console.log('done card',C[j],'key of',plr3.id)
                    //For player 1
                    var plr4 = sortedPlayers[3]
                    var key4 = plr4.cardEncryptionKey
                    // console.log('card',C[j],'key of',plr4.id,'| key',key4)
                    var result = await sym_decrypt(key4,C[j],game.symmetricEncryptionSettings.algorithm,game.symmetricEncryptionSettings.mode)
                    C[j] = result.cleartext
                    // console.log('done card',C[j],'key of',plr4.id)
                    initialHand.push(result.cleartext)
                    if(j == C.length-1){
                        // console.log('player',player.id,'had the following hand in the beginning',initialHand)
                        if(initialHand.find(x => x == card)){
                            // console.log(colors.yellow('Player ')+colors.red(accuser)+colors.yellow(' was WRONG in accusing '+colors.red(accused)))j
                            handleCheatingOutcome(accused,'PLAYED_MY_CARD',accuser,card,accused)
                        }else{
                            // console.log(colors.yellow('Player ')+colors.red(accuser)+colors.yellow(' was CORRECT! ')+colors.red(accused)+colors.yellow(' played his card!'))
                            handleCheatingOutcome(accused,'PLAYED_MY_CARD',accuser,card,accuser)
                        }
                    }
                }
            }else{
                console.log(colors.yellow('Player '+colors.red(player.id)+' DID NOT provide a valid bit commitment!'))
                sendSigned(client,{msg:'Player '+player.id+' DID NOT provide a valid bit commitment!'})
            }
        }
        game.num_ready += 1
        if(game.num_ready == 4){
            game.num_ready = 0
            broadcastMessageToGamePlayers(game,{
                status:'CHEATING_GAME_OVER',
            })
            stopGame(game)
        }
    }
}

function handleSignedReceipt(client,signature){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    game.receipt_signatures.push({id:player.id,signature})
    game.state = 'PRODUCING_RECEIPTS'
    if(game.receipt_signatures.length == 4){
        terminateGame(game)
    }
}

async function listGameHistory(client){
    var player = getPlayerFromClient(client)
    var rootDir = './game_accounting/'
    var dirName = `${rootDir}${player.id}/`
    var history = []
    try{
        if (fs.existsSync(rootDir)){
            if (fs.existsSync(dirName)){
                //listing all files using forEach
                var files = fs.readdirSync(dirName)
                for(var i in files){
                    if(player.certificate){
                        var contents = fs.readFileSync(dirName+files[i], 'utf8');
                        var g = JSON.parse(contents)
                        var msg_to_verify = `gameid${g.game_id}`
                        for(var j in g.players){
                            msg_to_verify += `id${g.players[j].id}points${g.players[j].points}`
                        }
                        var result = await rsa_verify_signed_certificate(player.certificate,msg_to_verify,g.signature)
                        if(result.valid){
                            console.log(colors.blue('File ')+colors.red(files[i])+colors.blue(' contains a valid game receipt of player ')+colors.red(player.id))
                            history.push(g)
                        }else{
                            console.log(colors.blue('File ')+colors.red(files[i])+colors.blue(' DOES NOT contain a valid game receipt of player ')+colors.red(player.id))
                        }
                    }else{
                        console.log(colors.blue('File ')+colors.red(files[i])+colors.blue(' DOES NOT contain a valid game receipt of player ')+colors.red(player.id))
                    }
                    if(i == files.length-1){
                        sendSigned(client,history)
                    }
                }
            }else{
                sendSigned(client,[])
            }
        }
    }catch(err){
        console.log(err)
    }
}

async function authenticateCitizenCard(client,username,dataIn){
    var {data,signature} = JSON.parse(decodeBase64(dataIn))
    var validSignature = await rsa_verify_signed_certificate(data.certificate,data.publicKey+data.certificate,signature)
    var validCertificate = await rsa_verify_chain_of_trust(data.certificate)
    console.log(validSignature)
    console.log(validCertificate)
    if(validCertificate.valid && validSignature.valid){ //TODO: REMOVE COMMENT TO CHECK BOTH CONDITIONS WHEN TESTING IS OVER
    //if(validSignature.valid){
        connectPlayer(client,username,data.publicKey)
        var player = getPlayerFromClient(client)
        player.certificate = data.certificate
        player.authenticationSignature = signature
        sendSigned(client,{publicKey:rsa_key_pair.publicKey})
        return true
    }
    return false
}

function handleRevealStage(client,key){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    game.state = 'REVEAL_STAGE'
    player.cardEncryptionKey = key
    var currentPlayerIndex = game.players.indexOf(player)
    if(currentPlayerIndex != 3){
        //Asks the next player for their bit commitment
        var nextPlayer = game.players[currentPlayerIndex+1]
        sendSigned(getClientFromPlayerID(nextPlayer.id),{
            status: 'START_REVEAL_STAGE',
        })
    }else{
        game.state = 'PLAYING_GAME'
        //All players sent their bit commitment, time for the reveal stage
        // console.log('key list', player_list.sort((x,y) => { return x.id.localeCompare(y.id) }).map(x => x.cardEncryptionKey))
        broadcastMessageToGamePlayers(game,{
            status:'END_REVEAL_STAGE',
            key_list: game.players.sort((x,y) => { return x.id.localeCompare(y.id) }).map(x => x.cardEncryptionKey)
        })
    }
}

function handleBitCommitment(client,R1,bitCommitment){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    game.state = 'BIT_COMMITMENT'
    player.bitCommitment = bitCommitment
    player.R1 = R1
    var currentPlayerIndex = game.players.indexOf(player)
    if(currentPlayerIndex != 3){
        //Asks the next player for their bit commitment
        var nextPlayer = game.players[currentPlayerIndex+1]
        sendSigned(getClientFromPlayerID(nextPlayer.id),{
            status: 'START_BIT_COMMITMENT',
        })
    }else{
        //All players sent their bit commitment, time for the reveal stage
        broadcastMessageToGamePlayers(game,{
            status:'END_BIT_COMMITMENT'
        })
        var nextPlayer = game.players[0]
        sendSigned(getClientFromPlayerID(nextPlayer.id),{
            status: 'START_REVEAL_STAGE',
        })
    }
}

function handleDeckDistributionFinished(client){
    var game = getGameFromPlayer(getPlayerFromClient(client))
    //Tells everyone that the distribution has ended
    broadcastMessageToGamePlayers(game,{
        status:'DISTRIBUTION_FINISHED'
    })
    //Tells the first player to start bit commitment
    var startingPlayer = game.players[0]
    sendSigned(getClientFromPlayerID(startingPlayer.id),{
        status: 'START_BIT_COMMITMENT',
    })
}

function distributeSecureChannelKeys(client){
    //When all keys have been received, distribuite to the corresponding players
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    var payloads = {}
    game.secure_channels.forEach((x,i,arr) => {
        var body = {
            sender: x.sender,
            msg: x.ciphertext
        }
        if(Object.keys(payloads).includes(x.target)){
            payloads[x.target].push(body)
        }else{
            payloads[x.target] = [body]
        }
    })
    sendSigned(client,payloads[player.id])
}

function distributeDeck(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    game.num_ready += 1
    if(game.num_ready == 4){
        game.num_ready = 0
        game.has_started = true
        game.state = 'DISTRIBUTING_DECK'
        var request = {
            process: 'distribute_deck',
            player_id:player.id
        }
        game.worker.postMessage(request)
    }
}

function returnDeck(client,encrypted_deck){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    var request = {
        process: 'return_deck',
        player_id: player.id,
        deck: encrypted_deck,
    }
    game.worker.postMessage(request)
}

function communicateSecureChannel(client_sender,client_target, msg){
    var player_sender = getPlayerFromClient(client_sender)
    sendSigned(client_target,{
        status:'SECURE_CHANNEL',
        sender:player_sender.id,
        cards:msg, //encrypted array of encrypted cards so that the server cannot calculate later the cards that each player has
    })
}

function connectPlayer(client,username,publicKey){
    var newPlayer = {
        id: username,
        socket:client,
        publicKey,
        certificate: null,
        authenticationSignature: null,
        bitCommitment:null,
        R1: null,
        cardEncryptionKey:null,
    }
    player_list.push(newPlayer)
    console.log(colors.blue('Player ')+ colors.red(newPlayer.id)+colors.blue(' has been logged in | Number of connected players:'+player_list.length))
}

function logIn(client,username,publicKey){
    connectPlayer(client,username,publicKey)
    sendSigned(client,{publicKey:rsa_key_pair.publicKey})
}

function waitingInLobby(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    sendSigned(client,{players:game.players.map(x => x.id)})
}

function playGame(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    game.num_ready += 1
    //If all players are ready. Play the game!
    if(game.num_ready == 4){
        game.num_ready = 0
        broadcastMessageToGamePlayers(game,{status:'OK'})
    }
}

function getGameFromGameID(game_id){
    return game_list.filter(x => x.id == Number(game_id))[0]
}

function findPlayerInGame(game,player){
    return game.players.find(x => x.id == player.id)
}

async function joinGame(client,game_id){
    var player = getPlayerFromClient(client)
    var game = getGameFromGameID(game_id)
    //Checks if the server has all the symetric and pub keys of the client trying to join
    //If not, may be a malicious party
    if(!findPlayerInGame(game,player)){
        console.log(colors.yellow('Joining '+colors.blue(player.id)+' to game '+colors.blue(game.id)))
        connectToGame(game,player)
    }//else, don't add the player to the game
}

function listPlayers(client){
    var payload = []
    player_list.forEach(x => payload.push({id: x.id}))
    for(var i in payload){
        var player = payload[i]
        var currently_connected_game = -1
        //If there are no games in the server, all players will be associated to no game
        if(game_list.length != 0)
            currently_connected_game = getGameFromPlayer(player)
        payload[i].game = currently_connected_game != -1 ? currently_connected_game.id : -1
    }
    sendSigned(client,payload)
}

function listGames(client){
    var payload = {
        game_list:game_list.map(x => x = {
        id:x.id,
        players: x.players.map(x => x = x.id),
        has_started: x.has_started,
        state:x.state,
    })}
    sendSigned(client,payload)
}

function getState(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    if(game != -1){
        var request = {
            process: 'get_state',
            player_id: player.id
        }
        game.worker.postMessage(request)
    }
}

async function playCard(client,card){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    var request = {
        process: 'play_card',
        player_id: player.id,
        card: card
    }
    game.worker.postMessage(request)
}

//////////////////////////////////////////////
////////////SECURITY FUNCTIONS////////////////
//////////////////////////////////////////////

function broadcastMessageToGamePlayers(game,msg){
    game.players.forEach(x => sendSigned(x.socket,msg))
}

async function establishSecureChannel(client_sender,client_target,ciphertext){
    var player_sender = getPlayerFromClient(client_sender)
    var player_target = getPlayerFromClient(client_target)
    var game = getGameFromPlayer(player_sender)
    var secure_channel = {
        sender:player_sender.id,
        target:player_target.id,
        ciphertext,
    }
    game.secure_channels.push(secure_channel)
    sendSigned(client_sender,{
        status: 'ESTABLISHED_CHANNEL'
    })
    if(allSecureConnectionsEstablished(game)){
        broadcastMessageToGamePlayers(game,{
            status: 'ESTABLISHED_ALL_CHANNELS'
        })
    }
}

function handleGamePlayersAuthentication(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    // console.log('game players: ',game.players)
    game.num_ready += 1
    if(game.num_ready == 4){
        game.num_ready = 0
        var msg = []
        game.players.forEach(plr => {
            msg.push({
                id:plr.id,
                certificate:plr.certificate,
                authenticationSignature:plr.authenticationSignature,
                publicKey:plr.publicKey
            })
            if(msg.length == 4){
                broadcastMessageToGamePlayers(game,msg)
            }
        })
    }
}

async function handleAcceptedPlayers(client,players){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    //Checks if the accepted player list is correct
    var playerList = game.players.map(x => x = x.id).sort((x,y) => { return x.localeCompare(y) })
    if(player.id == playerList[0]){
        game.symmetricEncryptionSettings = {
            algorithm: players[players.length-2],
            mode: players[players.length-1]
        }
        console.log(colors.yellow('Game '+colors.blue(game.id)+' has the following symmetric encryption settings: '),game.symmetricEncryptionSettings)
        players = players.slice(0,4)
    }
    var validPlayers = true
    for (var i = 0; i < players.length; i++) {
        if (players[i] !== playerList[i])
            validPlayers = false
    }
    if(!validPlayers){
        handleInvalidAcceptedPlayerList(client,player.id)
    }
    game.num_ready += 1
    if(game.num_ready == 4){
        game.num_ready = 0
        game.players.forEach((plr,i,arr) => {
            let public_keys = [...arr].filter(x => x.id != plr.id).map(x => x = {
                id: x.id,
                publicKey:x.publicKey,
            })
            sendSigned(getClientFromPlayerID(plr.id),{public_keys,encryption_settings:game.symmetricEncryptionSettings})
        })
    }
}

function hasAllRequiredKeys(player){
    if(!player.publicKey) return false
    return true
}

///////////////////////////////////////////////
////////////AUXILIAR FUNCTIONS/////////////////
///////////////////////////////////////////////

function resetPlayer(player){
    player.cardEncryptionKey = null
    player.bitCommitment = null
    player.R1 = null
}

async function stopGame(game){
    for(var i in game.players)
        resetPlayer(game.players[i])
    var result = await game.worker.terminate()
}

// num_secure_channels = n^2 + n, where n is the number of players
function allSecureConnectionsEstablished(game){
    return game.secure_channels.length == Math.pow(game.players.length,2)-game.players.length
}

function removePlayer(client){
    player_list = player_list.filter(x => client != x.socket) //Removes the player from the player list
}

function connectToGame (game,player) {
    if(!hasAllRequiredKeys(player)){
        throw 'Player '+player.id+' does not have all the required keys to join the game!'
    }
    var request = {
        process: 'connect',
        player_id: player.id
    }
    game.worker.postMessage(request) //connects the first player
    getGameFromGameID(game.id).players.push(player)
    var payload = {
        status: 'OK',
        id: game.id,
    }
    sendSigned(player.socket,payload)
}

async function disconnectFromGame(client){
    var player = getPlayerFromClient(client)
    var game = getGameFromPlayer(player)
    console.log(colors.yellow('Removing '+colors.blue(player.id)+' from game '+colors.blue(game.id)))
    // //If there was only 1 player left, ends the game
    game.num_ready += 1
    if(game.num_ready == 4){
        game.num_ready = 0
        for(i in game.players){
            var request = {
                process: 'end_game',
                player_id:game.players[i].id
            }
            game.worker.postMessage(request) //disconnects the player
        }
    }
}

function blackListPlayer(player,cheatingInfo){
    var rootDir = './black_list/'
    if (!fs.existsSync(rootDir)){
        fs.mkdirSync(rootDir);
    }
    var dirName = `${rootDir}${player.id}`
    if (!fs.existsSync(dirName)){
        fs.mkdirSync(dirName);
    }
    fs.appendFileSync(`${dirName}/player_${player.id}_game_${cheatingInfo.game}.json`,JSON.stringify(cheatingInfo));
}

function terminateGame(game){
    var data = game.game_result
    var players = game.players
    if(data)
        players = data.positions
    var rootDir = './game_accounting/'
    if (!fs.existsSync(rootDir)){
        fs.mkdirSync(rootDir);
    }
    for(var i = 0; i < players.length; i++){
        var payload = {
            signature:game.receipt_signatures.filter(x => x.id==players[i].id)[0].signature,
            game_id: game.id,
            players: players.map(x => x = {id:x.id,points:x.points})
        }
        var dirName = `${rootDir}${players[i].id}`
        if (!fs.existsSync(dirName)){
            fs.mkdirSync(dirName);
        }
        try {
            // fs.appendFileSync(`${dirName}/game_${game.id}.json`, JSON.stringify(payload)+'\n');
            fs.writeFileSync(`${dirName}/game_${game.id}.json`,JSON.stringify(payload));
        } catch(err) {
            // An error occurred
            console.error(err);
        }
        if(i == players.length - 1){
            var game = getGameFromPlayer(getPlayerFromClient(getClientFromPlayerID(players[i].id)))
            console.log(colors.yellow('Closing game ')+colors.blue(game.id)+colors.yellow(' for lack of players'))
            broadcastMessageToGamePlayers(game,JSON.stringify({
                status:'STOP_GAME',
            }))
            stopGame(game)
        }
    }
}

function getGameFromPlayer(player) {
    var game = game_list.filter(x => x.players.find(y => y.id == player.id))
    return game.length != 0 ? game[0] : -1
}

function getPlayerFromClient(client){
    return player_list.filter(x => x.socket == client)[0]
}

//Returns 1 if player_id is invalid
function getClientFromPlayerID(player_id){
    var player = player_list.filter(x => x.id == player_id)
    if(player.length == 0) return -1
    return player[0].socket
}

function handleCheatingOutcome(accused_id,status,accuser_id,card,outcome){
    if(status == 'PLAYED_MY_CARD'){
        status = 'playing his card '+card
    }else if(status == 'PLAYED_CARD_TWICE'){
        status = 'playing '+card+' twice'
    }else if(status == 'RENOUNCE'){
        status = 'renouncing the game with card '+card
    }
    let reason = null
    let culprit = null
    //If it isn't the accused's fault
    if(outcome == accused_id){
        console.log(colors.yellow('Player ')+colors.red(accuser_id)+colors.yellow(' was WRONG in accusing '+colors.red(accused_id))+colors.yellow(' of ')+colors.yellow(status))
        reason = 'Player '+accuser_id+' was WRONG in accusing '+accused_id+' of '+status
        culprit = accuser_id
    } //If it the accused's fault
    else if(outcome == accuser_id){
        console.log(colors.yellow('Player ')+colors.red(accuser_id)+colors.yellow(' was CORRECT in accusing '+colors.red(accused_id))+colors.yellow(' of ')+colors.yellow(status))
        reason = 'Player '+accuser_id+' was CORRECT in accusing '+accused_id+' of '+status
        culprit = accused_id
    }
    let game = getGameFromPlayer(getPlayerFromClient(getClientFromPlayerID(accused_id)))
    broadcastMessageToGamePlayers(game,{msg:reason})
    blackListPlayer(getPlayerFromClient(getClientFromPlayerID(culprit)),{game:game.id,accuser_id,accused_id,reason})
}

function createGame (player) {
    //Creates a new thread for the new game table
    const id = Math.floor(Math.random() * 100000000000)
    const worker = new Worker('./hearts.js', {
        workerData: id
    });
    worker.on('online', () => { //Adds the game table to the list
        var game = {
            id,
            players: [],
            has_started: false,
            worker,
            state: 'WAITING_FOR_PLAYERS',
            num_ready: 0,
            receipt_signatures: [],
            game_result: null,
            cheating_info: null,
            secure_channels: [], //secure channels established between players
            symmetricEncryptionSettings: null
        }
        game_list.push(game)
        connectToGame(game,player)
    })
    worker.on('message', (data) => {
        var payload = null
        switch(data.status){
            case 'GAME_OVER':
                payload = data
                var game = getGameFromPlayer(getPlayerFromClient(getClientFromPlayerID(data.id)))
                game.game_result = data
                break
            case 'WINNER_OF_HAND':
                payload = {
                    status: data.status,
                    id: data.id,
                    handWinner: data.msg, // the id of the winner
                    cards: data.cards // the cards that the winner got
                }
                break
            case 'GET_STATE':
                payload = {
                    status: data.status,
                    id: data.id,
                    cards:data.cards
                }
                break
            case 'CARDS_ON_TABLE':
                payload = {
                    status: data.status,
                    id: data.id,
                    cards:data.cards
                }
                break
            case 'END_GAME':
                payload = {
                    status: data.status,
                    id: data.id,
                    positions: data.msg.map(x => x = {
                        id:x.id,
                        points:x.points
                    }),
                }
                break
            case 'DECK_DISTRIBUTION':
                payload = {
                    id: data.id,
                    status: data.status,
                    cards: data.cards
                }
                break
            case 'CARD_DISTRIBUTION':
                payload = {
                    id: data.id,
                    status: data.status,
                    cards: data.cards
                }
                break
            case 'DISTRIBUTION_FINISHED':
                payload = {
                    id: data.id,
                    status: data.status,
                }
                break
            case 'ILLEGAL_PLAY':
                payload = {
                    status:data.status,
                    id:data.id,
                    msg:data.msg
                }
                break
            case 'PLAYED_CARD_TWICE':
                payload = {
                    status:data.status,
                    id:data.id,
                    msg:data.msg,
                    card:data.cards,
                }
                handleCheatingOutcome(data.id,data.status,data.msg.accuser_id,data.cards,data.msg.outcome)
                break
            case 'RENOUNCE':
                payload = {
                    status:data.status,
                    id:data.id,
                    msg:data.msg,
                    card:data.cards,
                }
                handleCheatingOutcome(data.id,data.status,data.msg.accuser_id,data.cards,data.msg.outcome)
                break
        }
        // console.log(payload)
        sendSigned(getClientFromPlayerID(data.id),payload)
    });
    worker.on('error', (err)=>{
        console.log(err)
    });
    worker.on('exit', (code) => {
        var g = game_list.filter(x => x.worker == worker)[0]
        game_list = game_list.filter(x => x.worker != worker)
        console.log(colors.green('Worker of game ')+colors.blue(g.id)+colors.green(' is being terminated intencionaly'))
    });
}

server.listen(PORT, IP_ADDRESS,async ()=>{
    console.log('Coupier listening on',IP_ADDRESS+":"+PORT)
    //Generates an rsa key pair for secure comm between players and server
    // rsa_key_pair = await rsa_generate_key_pair(RSA_PASSWORD)
    //saves the server public key in a file known to all clients
    // fs.writeFileSync("../security/server_pubkey.PEM", rsa_key_pair.publicKey,(err)=>{});
    // fs.writeFileSync("../security/server_privateKey.PEM", rsa_key_pair.privateKey,(err)=>{});
    rsa_key_pair = {}
    rsa_key_pair.publicKey = fs.readFileSync("../security/server_pubkey.PEM", 'utf8');
    rsa_key_pair.privateKey = fs.readFileSync("../security/server_privateKey.PEM", 'utf8');
    // console.log('Loaded server RSA KEY PAIR is',rsa_key_pair)
});