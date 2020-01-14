import socket
import time
import random
from aux import *
from graphic_interface import * 

############### Functions for the game ####################

def play_game(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings):
    clear_screen()
    return play_round(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings)


def play_round(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings):
    num_cards_played = 0 #when all 4 players have played 1 card this variable is incremented. when a new round starts its set to 0
    playing = False
    starting_hand = None
    cards_on_table = None
    next_to_play = None
    R1 = None
    R2 = None
    C = None
    oponnent_hands = {}
    suit_hand_player = {}
    currentSuit = None
    for p in players:
        if p != player_id:
            oponnent_hands[p] = []
            suit_hand_player[p] = {}
            for s in ['H', 'D', 'S', 'C']: #No inicio do jogo assume se que todos os jogadores tem todos os naipes
                #print('suit %s'% s)
                suit_hand_player[p][s]=1 #1-tem o naipe; se não joga o mesmo naipe assume se que o jogador nao tem o naipe(0)
    
    hand = []
    #### Security attributes ####
    while True:
        #Atribute initialization
        #If it's the first time playing
        if len(hand) == 0:
            #Game is over
            if num_cards_played != 0:
                positions = None
                while num_cards_played % 4 != 3:
                    positions = verify_and_receive(sock,rsa_server)
                    card = list(filter(lambda x : x['id'] == next_to_play,positions['cards']))[0]['cardPlayed']
                    reason = False
                    if next_to_play != player_id:
                        cli = interface_validate_play()
                        valid = True if cli.launch() == 'Yes' else False
                        if not valid:
                            cli = interface_cheating_reason()
                            reason = cli.launch()
                    leftover_state = validate_card_played(sock,rsa_server,rsa_client,starting_hand,player_id,next_to_play,card,oponnent_hands,suit_hand_player,R1,R2,C,{'valid':valid,'reason':reason})
                    if leftover_state == 'CHEATING_GAME_OVER':
                        print('The game has been ended because of cheating. SHAME!')
                        return 'CHEATING_GAME_OVER'
                    if next_to_play != player_id:
                        oponnent_hands[next_to_play].append(card)
                    for j in positions['cards']:
                        if j['playing'] == 1:
                            next_to_play = j['id']
                    # print('Oponnent %s of %s played %s'%(next_to_play,player_id,card))
                    num_cards_played += 1
                positions = verify_and_receive(sock,rsa_server)
                lastHandWinner = verify_and_receive(sock,rsa_server)
                #Accounts for the last played card
                card = list(filter(lambda x : x['id'] == next_to_play,positions['cards']))[0]['cardPlayed']
                if next_to_play != player_id:
                    cli = interface_validate_play()
                    valid = True if cli.launch() == 'Yes' else False
                    if not valid:
                        cli = interface_cheating_reason()
                        reason = cli.launch()
                leftover_state = validate_card_played(sock,rsa_server,rsa_client,starting_hand,player_id,next_to_play,card,oponnent_hands,suit_hand_player,R1,R2,C,{'valid':valid,'reason':reason})
                if leftover_state == 'CHEATING_GAME_OVER':
                    print('The game has been ended because of cheating. SHAME!')
                    return 'CHEATING_GAME_OVER'

                if next_to_play != player_id:
                    oponnent_hands[next_to_play].append(card)
                # print('Oponnent %s of %s played %s'%(next_to_play,player_id,card))

                positions['cards'].sort(key=lambda x: x['points'], reverse=False)
                print_final_positions(positions['cards'])
                break
            else:
                hand, R1, R2, C = secure_deck_distribution(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings)
                # print('R1 value is ',R1)
                # print('R2 value is ',R2)
                starting_hand = [c for c in hand]
                state = {'status':'FIRST_PLAY', 'cards':hand}
        else:
            state = verify_and_receive(sock,rsa_server)

        #Has to listen
        if state['status'] == 'CARDS_ON_TABLE':
            playing = False
            card = None
            cards_on_table = state['cards']
            clear_screen()
            print(separator)
            print_cards_on_table(cards_on_table,player_id)
            if num_cards_played != 0:
                card = list(filter(lambda x : x['id'] == next_to_play,cards_on_table))[0]['cardPlayed']
                currentSuit = state['cards'][0]['currentSuit']
                p_id = next_to_play
            else:
                card = '2|C'
                currentSuit = 'C'
                p_id = list(filter(lambda x : x['cardPlayed'] == card,cards_on_table))[0]['id']
            ################# Cheating detection #################
            reason = False
            if p_id != player_id:
                cli = interface_validate_play()
                valid = True if cli.launch() == 'Yes' else False
                if not valid:
                    cli = interface_cheating_reason()
                    reason = cli.launch()
            leftover_state = validate_card_played(sock,rsa_server,rsa_client,starting_hand,player_id,p_id,card,oponnent_hands,suit_hand_player,R1,R2,C,{'valid':valid,'reason':reason})
            if leftover_state == 'CHEATING_GAME_OVER':
                print('The game has been ended because of cheating. SHAME!')
                return 'CHEATING_GAME_OVER'

            #If it is a valid play tracks this card and continues the game
            if p_id != player_id:
                oponnent_hands[p_id].append(card)
                #if the card is of a different suit than the currentSuit card, it indicates that the current player no longer has that suit in his deck
                if card.split('|')[1] != currentSuit:
                    suit_hand_player[p_id][currentSuit] = 0
                    # print('Oponnent %s of %s have not suit %s'%(p_id,player_id,currentSuit))
            # print('Oponnent %s of %s played %s'%(p_id,player_id,card))

            for j in cards_on_table:
                if j['playing'] == 1:
                    # print(player_id,' next to play is',next_to_play)
                    next_to_play = j['id']
                    if j['id'] == player_id:
                        playing = True
                        break
            num_cards_played += 1
            if num_cards_played % 4 == 0:
                state = leftover_state
        if state['status'] == 'WINNER_OF_HAND':
            next_to_play = state['handWinner']
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
        # print('Next player playing is %s'%next_to_play)
        
        if num_cards_played == 0:
            #The case of the first play
            if '2|C' in hand:
                playing = True
            else:
                playing = False
        #Playing mechanism
        if playing:
            card = None
            valid = False
            cheating = False
            while not valid:
                #The player with 2 of clubs has to start
                card = interface_play_card(hand)
                if card == cheating_prompt:
                    cheating = True
                    cli = interface_cheat_card()
                    card = cli.launch()
                if '2|C' in hand and card != '2|C':
                    clear_screen()
                    print(separator)
                    print('You must play the 2♣ in your hand.\n')
                else:
                    valid = True
            
            #Signs the card
            signature = play_card_server(sock,rsa_client,card)
            # print('Signature of card %s of player %s is %s'%(card,player_id,signature))
            if not cheating:
                hand.remove(card)
            playing = False
            clear_screen()
            print(separator)
            
        #CHEATING
        if state['status'] == 'PLAYED_CARD_TWICE' or state['status'] == 'RENOUNCE':
            print('The game has been ended because of cheating. SHAME!')
            return 'CHEATING_GAME_OVER'
            
        
