const {Worker,isMainThread, parentPort,workerData} = require('worker_threads')
var {rsa_generate_key_pair,
    rsa_decrypt,
    rsa_encrypt,
    aes_decrypt,
    aes_encrypt,
    encodeBase64,
    decodeBase64} = require('./security_interface')
    
const SUITS = ['H', 'D', 'S', 'C']  //Hearts, diamonds, spaces and clubs
const VALUES = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']
const MAX_POINTS = 10

var players = []
var turn = 1
var currentTable = [null,null,null,null] //cards that are currently on the table
var currentSuit = null
var currentSuitList = []
var deck = null
var cardsPlayed = []
var currentPlayerPlaying = -1


var game_id = workerData

parentPort.on('message',(msg)=>{
    switch(msg.process){
        case 'distribute_deck':
            distributeDeck()
            break
        case 'return_deck':
            returnDeck(msg.deck)
            break
        case 'connect':
            connectPlayer(msg.player_id)
            break
        case 'end_game':
            endGame(msg.player_id)
            break
        case 'play_card':
            playCard(msg.player_id,msg.card)
            break
        case 'check_played_twice':
            checkPlayedTwice(msg.accuser,msg.accused,msg.card)
            break
        case 'check_renounce':
            checkRenounce(msg.accuser,msg.accused,msg.card)
            break
    }
})

/////////Processes functions//////////
function checkRenounce(accuser_id,accused_id,card){
    var accused = getPlayerFromID(accused_id)
    var hand = accused.hand
    var suits = {'H':true, 'D':true, 'S':true, 'C':true}
    for(let i in hand){
        //If the accused played this card
        if(hand.find(x => x == card)){
            var value = getCardValue(hand[i])
            var suit = getCardSuit(hand[i])
            if(!suits[suit]){
                sendResponse(accused.id,'RENOUNCE',{outcome:accuser_id,accuser_id},card)
                break
            }
            if(suit != currentSuitList[i]){
                suits[currentSuitList[i]] = false
            }
            if(i == hand.length-1){
                //Announce whose fault it is
                sendResponse(accused.id,'RENOUNCE',{outcome:accused_id,accuser_id},card)
            }
        }
    }
}

function checkPlayedTwice(accuser_id,accused_id,card){
    var accused = getPlayerFromID(accused_id)
    var cardsPlayedBeforeLastRound = accused.hand.slice(0,accused.hand.length-1)
    if(cardsPlayedBeforeLastRound.find(x => x == card)){
        sendResponse(accused.id,'PLAYED_CARD_TWICE',{outcome:accuser_id,accuser_id},card)
    }else{
        sendResponse(accused.id,'PLAYED_CARD_TWICE',{outcome:accused_id,accuser_id},card)
    }
}

function distributeDeck(){
    var nextPlayer = playerListSorted()[0]
    //passes the deck to the first player in alphabetical order of the id
    shuffleDeck()
    sendResponse(nextPlayer.id,'DECK_DISTRIBUTION',null,deck)
}

function returnDeck(encrypted_deck){
    var nextPlayer = playerListSorted()[0]
    sendResponse(nextPlayer.id,'CARD_DISTRIBUTION',null,encrypted_deck)
}

function broadcastHandWinner(winner,cardPool){
    for(var i in players){
        sendResponse(players[i].id,'WINNER_OF_HAND',winner.id,cardPool)
    }
}

function broadcastTableState(){
    if(currentPlayerPlaying != -1){
        var p1Playing = currentPlayerPlaying == 0 ? 1 : 0
        var p2Playing = currentPlayerPlaying == 1 ? 1 : 0
        var p3Playing = currentPlayerPlaying == 2 ? 1 : 0
        var p4Playing = currentPlayerPlaying == 3 ? 1 : 0
    }else{//still figuring out which player has the 2C
        var p1Playing = 2 
        var p2Playing = 2
        var p3Playing = 2
        var p4Playing = 2
    }
    var cardsOnTable = [{
        id:players[0].id,
        cardPlayed:currentTable[0] ? currentTable[0] : 0,
        turn,
        playing:p1Playing,
        currentSuit,
        points:players[0].points,
    },{
        id:players[1].id,
        cardPlayed:currentTable[1] ? currentTable[1] : 0,
        turn,
        playing:p2Playing,
        currentSuit,
        points:players[1].points,
    },{
        id:players[2].id,
        cardPlayed:currentTable[2] ? currentTable[2] : 0,
        turn,
        playing:p3Playing,
        currentSuit,
        points:players[2].points,
    },{
        id:players[3].id,
        cardPlayed:currentTable[3] ? currentTable[3] : 0,
        turn,
        playing:p4Playing,
        currentSuit,
        points:players[3].points,
    }]
    //Broadcasts to everyone the state of the table
    for(var i = 0; i < players.length; i++)
        sendResponse(players[i].id,'CARDS_ON_TABLE',null,cardsOnTable)
}

function connectPlayer(player_id){
    players.push({
        id: player_id,
        hand: [],
        points:0,
        wonCards:[],
        readyToEnd:false,
        suitHand: {},
    })
}

function numReadyToEndGame(){
    return players.filter(x => x.readyToEnd).length
}

function endGame(player_id){
    players[getIndexOfPlayer(player_id)].readyToEnd = true
    if(numReadyToEndGame() == 4){
        var sortedPlayers = [...players]
        sortedPlayers = sortedPlayers.sort((x,y) => {return x.points-y.points})
        for(i in players){
            parentPort.postMessage({
                id:players[i].id,
                positions:sortedPlayers,
                status:'GAME_OVER',
                msg:'The game has ended',
                game_id,
            })
        }
    }
}

function playCard(player_id,card){
    //If it's the first play, the card must be the 2C
    if(numCardsPlayedThisRound() == 0){
        //If it's the first turn waits to find out who has 2C
        if(turn == 1){
            if(getCardValue(card) != '2' || getCardSuit(card) != 'C'){
                sendResponse(player_id,'ILLEGAL_PLAY','The first card to be played must be 2C',null)
                return
            }
            currentPlayerPlaying = getIndexOfPlayer(player_id)
        }
        else{ //If it isn't the first play the first player is the winner of the previsous hand
            if(player_id != players[currentPlayerPlaying].id){ //If a player other than the previous winner plays a card it's aborted
                sendResponse(player_id,'ILLEGAL_PLAY','It is not your turn to play.')
                return
            }
        }
        currentSuit = getCardSuit(card)
        currentSuitList.push(currentSuit)
    }
    var player = getPlayerFromID(player_id)
    suitHand(player, card)
    trackPlayerCard(card,player)
    placeCardOnTable(card,player)
    if(numCardsPlayedThisRound() == 4){
        var cardPool = [...currentTable]
        var tableWinner = getTableWinner()
        tableWinner.wonCards = tableWinner.wonCards.concat(cardPool) //attributes the winnings to the player to keep track
        tableWinner.points += countPoints(cardPool)
        broadcastTableState() //send the new state of the table to every player
        broadcastHandWinner(tableWinner,cardPool)
        if(playersLeftToDealHand() == 4){
            clearRound()
        }else{
            clearTable(tableWinner,cardPool)
        }
    }else{
        currentPlayerPlaying = getNextPlayer(currentPlayerPlaying,0)
        broadcastTableState() //send the new state of the table to every player
    }
}

/////////Auxiliar functions///////////
function playerListSorted(){
    return players.sort((x,y) => { return x.id.localeCompare(y.id) })
}

function clearRound(){
    currentTable = [null,null,null,null] //cards that are currently on the table
    currentSuit = null
    deck = null
    turn = 1
    currentPlayerPlaying = -1
    for(i in players){
        players[i].wonCards = []
    }
    //Checks if the game has ended
    if(players.filter(x => x.points >= MAX_POINTS).length > 0){
        players.sort((x,y) => {return x.points-y.points})
        for(i in players){
            sendResponse(players[i].id,'END_GAME',players,null)
        }
    }
}

function countPoints(cards){
    var points = 0
    for(i in cards){
        if(getCardValue(cards[i]) == 'Q' && getCardSuit(cards[i]) == 'S') points += 13
        else if(getCardSuit(cards[i]) == 'H') points +=1
    }
    return points
}

function clearTable(player,cards){
    currentPlayerPlaying = getIndexOfPlayer(player.id)
    currentTable = [null,null,null,null]
    turn += 1
}

function getCardSuit(card){
  return card.split('|')[1]
}

function getCardValue(card){
  return card.split('|')[0]
}

function higherThan(card1, card2){
    var i1 = VALUES.indexOf(getCardValue(card1))
    var i2 = VALUES.indexOf(getCardValue(card2))
    if(i1 > i2) return 1
    else if(i1 < i2) return -1
    return 0
}

function getTableWinner(){
    var currentSuitCards = currentTable.filter(x => getCardSuit(x) == currentSuit)
    var highest = currentSuitCards[0]
    for(i in currentSuitCards){
        if(higherThan(currentSuitCards[i],highest) > 0){
          highest = currentSuitCards[i]
        }
    }
    return players[currentTable.indexOf(highest)]
}

function numCardsPlayedThisRound(){
    return currentTable.filter(x => x != null).length
}

function placeCardOnTable(card,player){
    currentTable[getIndexOfPlayer(player.id)] = card
}

function trackPlayerCard(card,player){
    cardsPlayed.push(card)
    player.hand.push(card)
}

function sendResponse(id, status, msg, cards){
    parentPort.postMessage({ id, status, msg, cards })
}

function getNextIndex(index,direction){
    if(direction % 4 == 0) //Pass to the left
      index = (index + 3) % 4
    else if(direction % 4 == 1)//Pass to the right
      index = (index + 1) % 4
    else if(direction % 4 == 2)//Pass to the front
      index = (index + 2) % 4
    return index
}

function getNextPlayer(index,dir){
    if(dir % 4 == 0) //Pass to the left
        index = (index + 3) % 4
    else if(dir % 4 == 1)//Pass to the right
        index = (index + 1) % 4
    else if(dir % 4 == 2)//Pass to the front
        index = (index + 2) % 4
    return index
}

function getIndexOfPlayer(player_id){
    for(var i = 0; i < players.length; i++)
        if(players[i].id == player_id) return i
    return -1
}

function getPlayerFromID(player_id){
    return players.filter(x => x.id == player_id)[0]
}

function playersLeftToDealHand(){
    return players.filter(x => x.hand.length == 0).length
}

function shuffleDeck(){
    //Initialize deck
    deck = [];
    SUITS.forEach((s) => {
        VALUES.forEach((v) => {
            deck.push(v + '|' + s);
        });
    });
    //Shuffle the actual deck
    deck = shuffleArray(deck)
}

function shuffleArray(array) {
    for (var i = array.length - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
    return array
}

function suitHand(player,card){
    for(var i=0;i<SUITS.length;i++){
        player.suitHand[SUITS[i]]=1;
        if(SUITS[i]==currentSuit){
            if(currentSuit!=getCardSuit(card)){
                player.suitHand[SUITS[i]]=0; 
            }
            else{
                player.suitHand[SUITS[i]]=1;
            } 
        }
    }
    return player
}
