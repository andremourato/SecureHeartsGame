import socket
import json
import sys
import base64
import random
import string
import hashlib
sys.path.insert(0,'../security/')
from citizen_card import *
from security import *
import time
import secrets

##########################################################
# FUNCTIONS FOR THE COMMUNICATION LAYER    
##########################################################

def get_all_players(sock,rsa_server,rsa_client):
    sign_and_send(sock,'LIST_PLAYERS',rsa_client)
    return verify_and_receive(sock,rsa_server)

def get_all_games(sock,rsa_server,rsa_client):
    sign_and_send(sock,'LIST_GAMES',rsa_client)
    raw = verify_and_receive(sock,rsa_server)
    return raw['game_list']

def get_game_history(sock,rsa_server,rsa_client):
    sign_and_send(sock,'LIST_GAME_HISTORY',rsa_client)
    return verify_and_receive(sock,rsa_server)

def join_croupier(address,username,citizen_card=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect the socket to the port where the server is listening
    server_address = (address, 3000)
    RSA_PASSWORD = generate_rsa_password()
    rsa_server = RSACipher()
    rsa_server.load_pub_key(load_server_public())
    rsa_client = RSACipher()
    client_keypair = rsa_client.generate_key_pair(RSA_PASSWORD)
    sock.connect(server_address)
    #Generates the client's key pair
    #########################################
    # 1 - Advertises the client's public key
    #########################################
    log_in_response = None
    if citizen_card: #If it is a citizen card authentication, then exchanges certificates
        cert = citizen_card.getCerts(0)
        content = {'publicKey':client_keypair['publicKey'],'certificate':base64.b64encode(cert).decode('utf-8')}
        data_to_be_signed = content['publicKey']+content['certificate']
        content_to_send = {'signature':base64.b64encode(citizen_card.sign(0, data_to_be_signed)).decode('utf-8'),'data':content}
        #print(base64.b64encode(bytes(json.dumps(content_to_send),'utf-8')).decode('utf-8'))
        sock.sendall(bytes('CITIZEN_CARD_AUTHENTICATION:%s:%s'%(username,base64.b64encode(bytes(json.dumps(content_to_send),'utf-8')).decode('utf-8')),'utf-8'))
        log_in_response =  verify_and_receive(sock,rsa_server)
    else:
        sign_and_send(sock,'LOG_IN:%s:%s'%(username,client_keypair['publicKey']),rsa_client,True)
        log_in_response = verify_and_receive(sock,rsa_server) #verifies that the public key is from the server (useless but just for testing)

    if 'error' in log_in_response:
        return 'ERROR', log_in_response['error'], None, None
    ###########################################################################################################################
    # 2 - Creates a secure channel with the server (encrypts sym key with server public key and sends it to the server)
    ###########################################################################################################################
    return sock, rsa_server, rsa_client

def leave_croupier(sock):
    sock.close()

def create_game(sock,rsa_server,rsa_client):
    sign_and_send(sock,'CREATE_GAME',rsa_client)
    return verify_and_receive(sock,rsa_server)

def join_game(sock,game_id,rsa_server,rsa_client):
    sign_and_send(sock,'JOIN_GAME:%s'%(game_id),rsa_client)
    return verify_and_receive(sock,rsa_server)

def wait_in_lobby(sock,rsa_server,rsa_client):
    sign_and_send(sock,'WAITING_IN_LOBBY',rsa_client)
    return verify_and_receive(sock,rsa_server)['players']

def play_game_server(sock,rsa_server,rsa_client):
    sign_and_send(sock,'PLAY_GAME',rsa_client)
    return verify_and_receive(sock,rsa_server)

def game_accounting(sock,rsa_server,rsa_client,game_result,citizen_card):
    positions = game_result['positions']
    msg = 'gameid%s'%(game_result['game_id'])
    for player in positions:
        msg += 'id%spoints%s'%(player['id'],player['points'])
    signature = None
    # if player has a citizen card signs with the card's privatekey
    if citizen_card:
        print('Please insert your citizen card PIN: ')
        signature = base64.b64encode(citizen_card.sign(0,msg)).decode('utf-8')
    #else signs with the current private Key that was generated automatically
    else:
        print('This player doesn\'t have a cc card')
        signature = rsa_client.sign(msg)
    #provides the signature
    sign_and_send(sock,'SIGNED_RECEIPT:%s'%(signature),rsa_client,True)
    return verify_and_receive(sock,rsa_server) #status: "STOP_GAME"

def leave_lobby(sock,rsa_server,rsa_client):
    sign_and_send(sock,'LEAVE_LOBBY',rsa_client)
    return verify_and_receive(sock,rsa_server)

def recvall(sock):
    # Helper function to recv n bytes or return None if EOF is hit
    result = ''
    while True:
        packet = sock.recv(1024)
        result += packet.decode('utf-8')
        try:
            res = json.loads(result)
            return result
        except:
            continue

##########################################################
# Security functions      
##########################################################

def secure_deck_distribution(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings):
    sign_and_send(sock,'CLIENT_DISTRIBUTE_DECK',rsa_client)
    # 1 - Each player encrypts
    result = distribute_deck(sock,rsa_server,rsa_client,player_keys,players,player_id,encryption_settings)
    hand = result[0]
    # print('Player %s hand is %s'%(player_id,hand))
    deck_encryption_key = result[1]
    R1,R2,C = send_bit_commitment(sock,rsa_server,rsa_client,players,player_id,hand)
    return reveal_stage(sock,rsa_server,rsa_client,players,player_id,hand,deck_encryption_key,encryption_settings), R1, R2, C


def load_server_public():
    file_pubkey = open('../security/server_pubkey.PEM','r')
    return file_pubkey.read()
    
def notify_server_players_accepted(sock,rsa_server,rsa_client,players,player_id,cipher_algorithm,cipher_mode):
    master_keys = {}
    #Verify the identity of all the other players
    sign_and_send(sock,'GAME_PLAYERS_AUTHENTICATION',rsa_client)
    player_authentication = verify_and_receive(sock,rsa_server)
    # print('received ',player_authentication)
    for plr in player_authentication:
        # If the player doesn't have a citizen card, it doesn't try to validate anything
        if plr['id'] != player_id:
            if plr['certificate'] != None:
                if plr['id'] in players:
                    print('Verifying certificate of player ',plr['id'])
                    try:
                        valid_signature = verify_signed_certificate(plr['certificate'],plr['publicKey']+plr['certificate'],plr['authenticationSignature'])
                        rootCerts, trustedCerts, crlList = load_certificates_and_revogation_lists()
                        ccStoreContext = ccStore(rootCerts, trustedCerts, crlList)
                        valid_chain_of_trust = verify_chain_of_trust(plr['certificate'],ccStoreContext)
                        # print('chain of trust ',valid_chain_of_trust)
                        if not valid_signature or not valid_chain_of_trust: #Remove comment if you want to check for valid chain of trust
                        #if not valid_signature:
                            print('Could not authenticate player ',plr['id'],'.Shutting down!')
                            exit(3)
                    except:
                        print('Could not authenticate player ',plr['id'],'.Shutting down!')
                        exit(3)
                    print('The signature and certificate of ',plr['id'],' are both valid!')
                else:
                    print('Player ',plr['id'],' is not in the player list presented by the server')
            else:
                print('Player ',plr['id'],' does not have a Citizen Card, so it does not have a certificate. Skipping.')

    #If the identity is valid send a message accepting to play
    sorted_players = sorted(players)
    sign_and_send(sock,'ACCEPTED_PLAYERS:%s'%(':'.join(sorted_players)+
                                            #If this is the first players alphabetically, it chooses the symmetric encryption algorithm and mode to use
                                            ((':'+cipher_algorithm+':'+cipher_mode) if player_id == sorted_players[0] else '')),rsa_client,True)
    res = verify_and_receive(sock,rsa_server)
    public_keys = res['public_keys']
    encryption_settings = res['encryption_settings']
    print('%s is using %s and %s' % (player_id,encryption_settings['algorithm'],encryption_settings['mode']))
    print('The public keys from others: %s'%(public_keys))
    #For each player[i] encrypts the client's symetric key for secure communication with player[i] public key
    # print('Establishing %d secure channels' % len(public_keys))
    for i in range(len(public_keys)):
        sym_key = generate_random_password(16,16)
        print('Player %s sent player %s key: %s'%(player_id,public_keys[i]['id'],sym_key))
        master_keys[public_keys[i]['id']] = {'publicKey':public_keys[i]['publicKey'], 'symKey':sym_key}
        rsa_player = RSACipher()
        rsa_player.load_pub_key(public_keys[i]['publicKey'])
        sym_key_encrypted = rsa_player.encrypt(sym_key)
        master_keys[public_keys[i]['id']]['rsa'] = rsa_player
        sign_and_send(sock,'ESTABLISH_SECURE_CHANNEL:%s:%s'%(str(public_keys[i]['id']),sym_key_encrypted),rsa_client)
        res = verify_and_receive(sock,rsa_server)
    res = verify_and_receive(sock,rsa_server)
    # print('res ',res)
    # print('-----Got all public keys from the other clients and sent symmetric keys to them------')
    #receives the symetric keys from all other players encrypted with our public key
    #receives all symmetric keys encrypted
    sign_and_send(sock,'DISTRIBUTE_SECURE_CHANNEL_SYM_KEYS',rsa_client)
    result = verify_and_receive(sock,rsa_server)
    # print('result ',result)
    #For each other player in the game:
    #   - This player sends 1 symetric key, k1, and receives 1 symetric key, k2 (from the other player)
    #   - The symetric key, k1_xor_k2 between them is calculated by a bitwise xor between k1 and k2: k1_xor_k2 = k1 xor k2
    for i in range(len(result)):
        k1 = master_keys[result[i]['sender']]['symKey']
        k2 = base64.b64decode(rsa_client.decrypt(result[i]['msg']))
        k1_xor_k2 = bytes([b1 ^ b2 for b1, b2 in zip(k1, k2)])
        master_keys[result[i]['sender']]['symKey'] = k1_xor_k2
        symmetric_cipher = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
        print('%s is using %s and %s for symmetric encryption' % (player_id,encryption_settings['algorithm'],encryption_settings['mode']))
        # print('algo: %s | mode: %s'%(symmetric_cipher.algorithm,symmetric_cipher.mode))
        symmetric_cipher.generate_secret_key(base64.b64encode(master_keys[result[i]['sender']]['symKey']))
        master_keys[result[i]['sender']]['sym'] = symmetric_cipher
        print('%s\t%s\t%s' % (player_id,result[i]['sender'],master_keys[result[i]['sender']]['symKey']))
        del master_keys[result[i]['sender']]['symKey'] #If you need access to the public key and symetric key later remove these lines
        del master_keys[result[i]['sender']]['publicKey']
    # print('master keys ',master_keys)
    return master_keys, encryption_settings

def generate_random_password(mn,mx):
    return secrets.token_bytes(random.randint(mn,mx))

def generate_rsa_password():
    return generate_random_password(16,16)

def shuffle_deck(sock,rsa_server,rsa_client,player_keys,players,player_id,encryption_settings):
    #Waits to receive the deck to shuffle and encrypt
    raw = verify_and_receive(sock,rsa_server)
    # print('shuffle ',raw)
    deck = raw['cards']
    random.shuffle(deck)
    deck_sym_key = generate_random_password(16,16)
    sym_cipher = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
    # print('algo: %s | mode: %s'%(sym_cipher.algorithm,sym_cipher.mode))
    sym_cipher.generate_secret_key(base64.b64encode(deck_sym_key))
    # print(player_id,' deck before encrypt ',deck)
    encrypted_deck = [sym_cipher.encrypt(card) for card in deck]
    # print('%s deck after encrypt %s'%(player_id,encrypted_deck))
    #Passes to the next player
    sorted_players = sorted(players)
    next_index = sorted_players.index(player_id)+1
    print('%s encrypting with key %s'%(player_id,base64.b64encode(deck_sym_key).decode('utf-8')))
    #Returns the deck to the server if all players have shuffled
    if next_index == len(players):
        sign_and_send(sock,'RETURN_DECK:%s'%(':'.join(encrypted_deck)),rsa_client)
    else:
        next_player = sorted_players[next_index]
        print('%s is sending deck to %s '%(player_id,next_player))
        sign_and_send(sock,'SECURE_CHANNEL:%s:%s' % (next_player,':'.join(encrypted_deck)),rsa_client)
    return base64.b64encode(deck_sym_key).decode('utf-8')
    
def distribute_deck(sock,rsa_server,rsa_client,player_keys,players,player_id,encryption_settings):
    deck_sym_key = shuffle_deck(sock,rsa_server,rsa_client,player_keys,players,player_id,encryption_settings)
    #Choose to pick one card from the deck or do nothing and pass to a random player
    # print('player keys ',player_keys)
    hand = []
    remaining_deck = None
    while True:
        #If it still needs to pick cards
        print('%s has %d cards in hand' % (player_id,len(hand)))
        remaining_deck = verify_and_receive(sock,rsa_server)
        # print('rem ',remaining_deck)
        #In case this is not the last player to take a card
        if remaining_deck['status'] == 'DISTRIBUTION_FINISHED':
            break
        if 'sender' in remaining_deck:
            remaining_deck = player_keys[remaining_deck['sender']]['sym'].decrypt(remaining_deck['cards']).split(':')
        else:
            remaining_deck = remaining_deck['cards']
        # print('Decrypted deck is ',remaining_deck)
        print('%s is distributing a deck with %d cards' %(player_id,len(remaining_deck)))
        if len(hand) < 13:
            prob = random.randint(0,100)
            #Probability table:
            # prob <= 20 -> picks up a card
            # 20 < prob <= 10+20 -> puts back x cards
            PROB_PICK_UP = 30
            PROB_PUT_BACK = 10
            if prob <= PROB_PICK_UP: #Picks a card. #TODO: CHANGE TO 10%: prob <= 10
                print('%s picked a card' % (player_id))
                hand.append(remaining_deck[0])
                remaining_deck = remaining_deck[1:]
            else:
                if len(hand) != 0 and prob > PROB_PICK_UP and prob <= PROB_PICK_UP+PROB_PUT_BACK: #Places n cards back in the deck
                    num_cards_to_put_back = random.randint(1,len(hand))
                    print('%s is putting back %d cards' % (player_id,num_cards_to_put_back))
                    # print('remaining ',remaining_deck)
                    # print('hand ',hand)
                    remaining_deck += hand[:num_cards_to_put_back]
                    hand = hand[num_cards_to_put_back:]
        #TODO: Assert that the information that goes through the server has the same length
        if len(remaining_deck) == 0 and len(hand) == 13:
            print('%s is shuffling a deck with %d cards' %(player_id,len(remaining_deck)))
            print('%s has %d cards in hand' % (player_id,len(hand)))
            sign_and_send(sock,'CLIENT_DISTRIBUTION_FINISHED',rsa_client)
        else:
            #Chooses another player to send the rest of the deck to (randomly)
            next_player = players[random.randint(0,3)]
            while next_player == player_id:
                next_player = players[random.randint(0,3)]
            print('%s is sending %s the remaining deck' % (player_id,next_player))
            enc_deck = player_keys[next_player]['sym'].encrypt(':'.join(remaining_deck))
            sign_and_send(sock,'SECURE_CHANNEL:%s:%s' % (next_player,enc_deck),rsa_client)
    print('%s has finished deck distribution and has %d cards on hand' % (player_id,len(hand)))
    return [hand,deck_sym_key]

def send_bit_commitment(sock,rsa_server,rsa_client,players,player_id,hand):
    print('%s is sending its bit commitment' % (player_id))
    #waits until server asks for its bit commitment
    r = verify_and_receive(sock,rsa_server)
    R1 = generate_random_password(16,16)
    R2 = generate_random_password(16,16)
    hash_object = hashlib.sha256()
    hash_object.update(R1)
    hash_object.update(R2)
    sorted_hand = sorted(hand)
    print('Player %s sorted encrypted hand is %s'%(player_id,sorted_hand))
    for enc_card in sorted_hand:
        hash_object.update(bytes(enc_card,'utf-8'))
    hex_dig = hash_object.hexdigest()
    print('The bit commitment of %s is %s'%(player_id,hex_dig))
    sign_and_send(sock,'CLIENT_BIT_COMMITMENT:%s:%s'%(base64.b64encode(R1).decode('utf-8'),hex_dig),rsa_client,True)
    r = verify_and_receive(sock,rsa_server)
    # print('Bit commitment has ended for %s with status %s'% (player_id,r['status']))
    return R1,R2,sorted_hand

def reveal_stage(sock,rsa_server,rsa_client,players,player_id,hand,deck_encryption_key,encryption_settings):
    # print('%s is in reveal stage'%(player_id))
    r = verify_and_receive(sock,rsa_server)#waits for the server to ask its encryption key
    sign_and_send(sock,'CLIENT_REVEAL_STAGE:%s' % (deck_encryption_key),rsa_client)
    r = verify_and_receive(sock,rsa_server) #waits for the server to send end_reveal_stage
    # print('r ',r)
    key_list = r['key_list'][::-1]
    print('List of card encryption keys of %s is %s'%(player_id,key_list))
    #For each card decrypts the ciphertext with the 4 keys
    for i in range(len(hand)):
        sym_client_1 = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
        # print('algo: %s | mode: %s'%(sym_client_1.algorithm,sym_client_1.mode))
        sym_client_1.generate_secret_key(key_list[0])
        hand[i] = sym_client_1.decrypt(hand[i])
        sym_client_2 = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
        # print('algo: %s | mode: %s'%(sym_client_2.algorithm,sym_client_2.mode))
        sym_client_2.generate_secret_key(key_list[1])
        hand[i] = sym_client_2.decrypt(hand[i])
        sym_client_3 = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
        # print('algo: %s | mode: %s'%(sym_client_3.algorithm,sym_client_3.mode))
        sym_client_3.generate_secret_key(key_list[2])
        hand[i] = sym_client_3.decrypt(hand[i])
        sym_client_4 = SymmetricCipher(encryption_settings['algorithm'],encryption_settings['mode'])
        # print('algo: %s | mode: %s'%(sym_client_4.algorithm,sym_client_4.mode))
        sym_client_4.generate_secret_key(key_list[3])
        hand[i] = sym_client_4.decrypt(hand[i])
    print('The decrypted hand of %s is %s'%(player_id,hand))
    return hand

def sign_and_send(sock,payload,rsa_client,sign=False):
    if sign:
        signature = rsa_client.sign(payload)
        sock.send(bytes('%s:%s'%(payload,signature),'utf-8'))
    else:
        sock.send(bytes('%s'%(payload),'utf-8'))

def verify_and_receive(sock,rsa_server):
    # t = time.time()
    received = recvall(sock)
    # elapsed = time.time() - t
    # print('Elapsed time in valid is: %ss'%(elapsed))
    result = json.loads(received)
    # print('result ',result)
    if 'signature' not in result:
        print('Message does not contain signature from the server!')
        exit(3)
    valid = rsa_server.verify(result['signature'],json.dumps(result['msg'],ensure_ascii=False, separators=(',', ':')))
    if not valid:
        print('Invalid signature from the server!')
        exit(3)
    return result['msg']

##########################################################
# FUNCTIONS FOR DETECTING CHEATING      
##########################################################
def validate_card_played(sock,rsa_server,rsa_client,player_starting_hand,player_id,current_player,card,oponnent_hands,suit_hand_player,R1,R2,C,manual_cheating_info=None):
    #0 - Loads the server pubkey and client private key
    to_return = None
    #1 - Initiates validation sequence
    sign_and_send(sock,'CHEATING_VERIFICATION_START',rsa_client)
    #2 - Waits to hear if there is cheating so far or not
    # print('waiting for server cheating status')
    result = verify_and_receive(sock,rsa_server)
    # print('player %s received:%s'%(player_id,result))
    if result['status'] == 'WINNER_OF_HAND': #TODO: SOLVE THE PROBLEM WHEN WINNER OF HAND IS EMITTED and cheating is not detected
        to_return = result
        #Checks cheating state again
        result = verify_and_receive(sock,rsa_server)
    #result = CHEATING_TURN_OVER_HAND if there is cheating previously else SEND_CHEATING_STATUS
    if result['status'] == 'SEND_CHEATING_STATUS':
        if manual_cheating_info is None:
            #3 - Checks if the played card is from this client
            # print('player %s is verifying cheating status for card %s with the following starting hand: %s'%(player_id,card,player_starting_hand))
            if current_player != player_id:
                if card in player_starting_hand:
                    print('CHEATING DETECTED! I\'M %s and %s PLAYED MY CARD %s!'%(player_id,current_player,card))
                    sign_and_send(sock,'CHEATING_VERIFICATION:%s:%s:%s'%('PLAYED_MY_CARD',current_player,card),rsa_client,True)
                    # print('player %s just sent status %s'%(player_id,'PLAYED_MY_CARD'))
                #the player played card twice 
                elif card in oponnent_hands[current_player]:
                    #print('player %s just sent status %s'%(player_id,'PLAYED_CARD_TWICE'))
                    print('CHEATING DETECTED! The %s PLAYED CARD %s TWICE!'%(current_player,card))
                    sign_and_send(sock,'CHEATING_VERIFICATION:%s:%s:%s'%('PLAYED_CARD_TWICE',current_player,card),rsa_client,True)
                elif suit_hand_player[current_player][card.split('|')[1]] == 0:
                    #print('Renuncia detetada, o jogador %s nao assistiu a este naipe %s numa jogada anterior'%(current_player, card.split('|')[1]))
                    print('CHEATING DETECTED! The %s PLAYED HAS RESIGNED!'%(current_player))
                    sign_and_send(sock,'CHEATING_VERIFICATION:%s:%s:%s'%('RENOUNCE',current_player,card),rsa_client,True)
                else:
                    sign_and_send(sock,'CHEATING_VERIFICATION:%s'%('ALL_GOOD'),rsa_client,True)
            #4 - If no cheating was found sends the ALL GOOD message
            else:
                sign_and_send(sock,'CHEATING_VERIFICATION:%s'%('ALL_GOOD'),rsa_client,True)
                # print('player %s just sent status %s'%(player_id,'ALL_GOOD'))
        else:
            if not manual_cheating_info['valid']:
                print('CHEATING DETECTED! I\'M %s and %s CHEATED %s!'%(player_id,current_player,card))
                sign_and_send(sock,'CHEATING_VERIFICATION:%s:%s:%s'%(manual_cheating_info['reason'],current_player,card),rsa_client,True)
                # print('player %s just sent status %s'%(player_id,'PLAYED_MY_CARD'))
            #4 - If no cheating was found sends the ALL GOOD message
            else:
                sign_and_send(sock,'CHEATING_VERIFICATION:%s'%('ALL_GOOD'),rsa_client,True)
                # print('player %s just sent status %s'%(player_id,'ALL_GOOD'))
        result = verify_and_receive(sock,rsa_server)
        # print('status received from server ',result)
    if result['status'] == 'CHEATING_TURN_OVER_HAND':
        # print('cheating detected')
        sign_and_send(sock,'CHEATING_TURNING_IN_HAND:%s:%s'%(base64.b64encode(R2).decode('utf-8'),':'.join(C)),rsa_client)
        cheating_msg = verify_and_receive(sock,rsa_server)
        print('Result of the cheating evaluation: %s'%(cheating_msg))
        to_return = 'CHEATING_GAME_OVER'
        

    return to_return

##########################################################
# FUNCTIONS FOR THE HEARTS GAME MECHANISM      
##########################################################

def play_card_server(sock,rsa_client,card):
    sign_and_send(sock,'PLAY_CARD:%s'%(card),rsa_client,True)