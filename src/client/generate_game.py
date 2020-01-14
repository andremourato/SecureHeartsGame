import socket
import threading
import time
import random
from prettytable import PrettyTable
from aux import *
from graphic_interface import *
from security import *
from random import randint
import sys

#Attribute init
global sockets
global games
global num_cards_played
global oponnent_hands
global suit_hand_player
global starting_hand
global next_to_play
global rsa_server
global rsa_client

#Attributes
DELAY_BETWEEN_PLAYS = 1 #in seconds
NUM_PLAYERS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
server_address = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'
print('GENERATING %d PLAYERS IN SERVER %s:3000'%(NUM_PLAYERS,server_address))
sockets = [None] * NUM_PLAYERS
threads = [None] * NUM_PLAYERS
games = [None] * NUM_PLAYERS
num_cards_played = [0] * NUM_PLAYERS


#Security algorithm and modes
cipher_algorithm = [None] * NUM_PLAYERS
cipher_mode = [None] * NUM_PLAYERS
encryption_settings = [None] * NUM_PLAYERS

#Security keys
rsa_server = [None] * NUM_PLAYERS
rsa_client = [None] * NUM_PLAYERS
player_keys = [None] * NUM_PLAYERS

#Cheating validation
oponnent_hands = [None] * NUM_PLAYERS
starting_hand = [None] * NUM_PLAYERS
next_to_play = [None] * NUM_PLAYERS
suit_hand_player = [None] * NUM_PLAYERS

#i = thread id
def generate_game(i):
    global sockets
    global games
    global server_address
    #1 - Connects to the server
    player_id = 'player_'+str(random.randint(1000,1000000))
    sockets[i], rsa_server[i], rsa_client[i] = join_croupier(server_address,player_id)
    print(player_id+' connected to croupier')
    #2 - Joins a game (creates if it doesn't exist)
    #The first player creates the game
    if i % 4 == 0:
        game = create_game(sockets[i],rsa_server[i],rsa_client[i])
        games[int(i/4)] = game['id']
    #The others join his game
    else:
        time.sleep(1) #to prevent join_game without game being created. first the game must be created. may not work sometimes
        join_game(sockets[i],games[int(i/4)],rsa_server[i],rsa_client[i])

    #3 - Waits for all 4 players in lobby
    print(player_id+' is waiting is lobby')
    players = wait_in_lobby(sockets[i],rsa_server[i],rsa_client[i])
    while(len(players)!=4):
        time.sleep(DELAY_BETWEEN_PLAYS) #waits for all 4 players to connect
        players = wait_in_lobby(sockets[i],rsa_server[i],rsa_client[i])

    #3.5 - Notifies the server that this player has accepted to play with all the other players
    encryption_algorithms = ['AES', 'Camellia', 'TripleDES', 'CAST5', 'SEED', 'Blowfish', 'IDEA']
    encryption_modes = ['CBC', 'OFB', 'CFB']
    cipher_algorithm[i] = encryption_algorithms[randint(0,len(encryption_algorithms)-1)]
    cipher_mode[i] = encryption_modes[randint(0,len(encryption_modes)-1)]
    print('%s chose %s and %s' % (player_id,cipher_algorithm[i],cipher_mode[i]))
    player_keys[i],encryption_settings[i] = notify_server_players_accepted(sockets[i],rsa_server[i],rsa_client[i],players,player_id,
                                        cipher_algorithm[i],cipher_mode[i])
    print(player_id+' has accepted to play with players')
    
    #4 - Starts the game
    data = play_game_server(sockets[i],rsa_server[i],rsa_client[i])
    if data['status'] != 'OK':
        print('Server did not give the OK to start the game!')
        exit(3)

    #5 - Play game
    r = play_round(i,player_id,players)
    if r != 'CHEATING_GAME_OVER':
        game_result = leave_lobby(sockets[i],rsa_server[i],rsa_client[i])
        game_accounting(sockets[i],rsa_server[i],rsa_client[i],game_result,None)
        print('CLEAN EXIT FOR PLAYER %s'%player_id)
    else:
        print('EXITING WITH STATUS ',r)
    exit(0)
        
def play_round(i,player_id,players):
    global sockets
    global num_cards_played
    global oponnent_hands
    global suit_hand_player
    global starting_hand
    global next_to_play
    time.sleep(DELAY_BETWEEN_PLAYS)
    starting_hand[i] = None
    playing = False
    end_of_round = False
    R1 = None
    R2 = None
    C = None
    #Atribute initialization
    cards_on_table = None
    next_to_play[i] = None
    oponnent_hands[i] = {}
    suit_hand_player[i] = {}
    currentSuit = None
    for p in players:
        if p != player_id:
            oponnent_hands[i][p] = []
            suit_hand_player[i][p] = {}
            for s in ['H', 'D', 'S', 'C']: #No inicio do jogo assume se que todos os jogadores tem todos os naipes
                #print('suit %s'% s)
                suit_hand_player[i][p][s]=1 #1-tem o naipe; se não joga o mesmo naipe assume se que o jogador nao tem o naipe(0)
    print('Oponnents of %s are %s'%(player_id,str(oponnent_hands[i])))
    hand = []
    #### Security attributes ####
    while True:
        #listens for data in tcp stream
        if len(hand) == 0:
            #Game is over
            if num_cards_played[i] != 0:
                positions = None
                while num_cards_played[i] % 4 != 3:
                    positions = verify_and_receive(sockets[i],rsa_server[i])
                    card = list(filter(lambda x : x['id'] == next_to_play[i],positions['cards']))[0]['cardPlayed']
                    #cheating validation
                    leftover_state = validate_card_played(sockets[i],rsa_server[i],rsa_client[i],starting_hand[i],player_id,next_to_play[i],card,oponnent_hands[i],suit_hand_player[i],R1,R2, C)
                    if leftover_state == 'CHEATING_GAME_OVER':
                        print('The game has been ended because of cheating. SHAME!')
                        return 'CHEATING_GAME_OVER'

                    if next_to_play[i] != player_id:
                        oponnent_hands[i][next_to_play[i]].append(card)
                    for j in positions['cards']:
                        if j['playing'] == 1:
                            next_to_play[i] = j['id']
                    print('Oponnent %s of %s played %s'%(next_to_play[i],player_id,card))
                    num_cards_played[i] += 1
                positions = verify_and_receive(sockets[i],rsa_server[i])
                lastHandWinner = verify_and_receive(sockets[i],rsa_server[i])
                #Accounts for the last played card
                card = list(filter(lambda x : x['id'] == next_to_play[i],positions['cards']))[0]['cardPlayed']
                #last cheating validation
                leftover_state = validate_card_played(sockets[i],rsa_server[i],rsa_client[i],starting_hand[i],player_id,next_to_play[i],card,oponnent_hands[i],suit_hand_player[i],R1,R2, C)
                if leftover_state == 'CHEATING_GAME_OVER':
                    print('The game has been ended because of cheating. SHAME!')
                    return 'CHEATING_GAME_OVER'

                if next_to_play[i] != player_id:
                    oponnent_hands[i][next_to_play[i]].append(card)
                print('Oponnent %s of %s played %s'%(next_to_play[i],player_id,card))

                positions['cards'].sort(key=lambda x: x['points'], reverse=False)
                print_final_positions(positions['cards'])
                break
            else: 
                hand, R1, R2, C = secure_deck_distribution(sockets[i],rsa_server[i],rsa_client[i],player_keys[i],player_id,players,encryption_settings[i])
                starting_hand[i] = [c for c in hand]
                state = {'status':'FIRST_PLAY', 'cards':hand}
        else:
            state = verify_and_receive(sockets[i],rsa_server[i])
        # print('State of %s is %s' % (player_id,state))
            
        if state['status'] == 'CARDS_ON_TABLE':
            playing = False
            card = None
            cards_on_table = state['cards']
            if num_cards_played[i] != 0:
                card = list(filter(lambda x : x['id'] == next_to_play[i],cards_on_table))[0]['cardPlayed']
                currentSuit = state['cards'][0]['currentSuit']
                p_id = next_to_play[i]
            else:
                card = '2|C'
                currentSuit = 'C'
                p_id = list(filter(lambda x : x['cardPlayed'] == card,cards_on_table))[0]['id']
            
            #################Cheating detection#################
            leftover_state = validate_card_played(sockets[i],rsa_server[i],rsa_client[i],starting_hand[i],player_id,p_id,card,oponnent_hands[i],suit_hand_player[i],R1,R2, C)
                    
            if leftover_state == 'CHEATING_GAME_OVER':
                print('The game has been ended because of cheating. SHAME!')
                return 'CHEATING_GAME_OVER'

            #If it is a valid play tracks this card and continues the game
            if p_id != player_id:
                oponnent_hands[i][p_id].append(card)
                #if the card is of a different suit than the currentSuit card, it indicates that the current player no longer has that suit in his deck
                if card.split('|')[1] != currentSuit:
                    suit_hand_player[i][p_id][currentSuit] = 0
                    #print('Oponnent %s of %s have not suit %s'%(p_id,player_id,card.split('|')[1])) 

            for j in cards_on_table:
                if j['playing'] == 1:
                    next_to_play[i] = j['id']
                    if j['id'] == player_id:
                        playing = True
                        break
            num_cards_played[i] += 1
            if num_cards_played[i] % 4 == 0:
                state = leftover_state
                # print('%s is reading winner of hand state %s'%(player_id,state))
        if state['status'] == 'WINNER_OF_HAND':
            next_to_play[i] = state['handWinner']
            #If he won, he is the next player to play
            if state['handWinner'] == player_id:
                print('You won this hand along with the cards '+str(state['cards']))
                playing = True
            else:
                print('The winner is '+str(state['handWinner'])+' and he won '+str(state['cards']))
                playing = False
            #Detects end of round
            if len(hand) == 0:
                print('End of round from player '+str(player_id))
                break
        
        print('Next player playing is %s'%next_to_play[i])

        if playing or '2|C' in hand:#Play the first card in the deck
            time.sleep(DELAY_BETWEEN_PLAYS) #Simulates a player thinking before playing
            # print('state of %s is %s'%(player_id,state))
            card = None
            if state['status'] == 'CARDS_ON_TABLE':
                current_suit = state['cards'][0]['currentSuit']
                for c in hand:
                    if c.split('|')[1] == current_suit:
                        card = c
                        break
                if card == None: #If he can't assist the current suit
                    card = hand[0]
            else:
                card = hand[0]
            if '2|C' in hand: card = '2|C'
            print(str(player_id)+' just played '+str(card))
            signature = play_card_server(sockets[i],rsa_client[i],card)
            # print('Signature of card %s of player %s is %s'%(card,player_id,signature))
            hand.remove(card)
            playing = False
        
        #CHEATING
        if state['status'] == 'PLAYED_CARD_TWICE' or state['status'] == 'RENOUNCE':
            print('The game has been ended because of cheating. SHAME!')
            return 'CHEATING_GAME_OVER' 
    # print('Oponnent hands of %s is %s'%(player_id,oponnent_hands[i]))


#Start of script
for i in range(NUM_PLAYERS):
    threads[i] = threading.Thread(target=generate_game,args=(i,))
    threads[i].start()


