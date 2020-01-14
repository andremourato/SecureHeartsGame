import socket
import sys
import json
import uuid #used to generate unique ids, remove later
import time
from hearts import *
from aux import *
from graphic_interface import *
from random import randint

##############################################################################
# CODE RELATED TO THE CLIENT APPLICATION AND COMMUNICATION WITH THE SERVER   #
##############################################################################

def main_menu():
    global connected
    global sock
    global player_id
    global player_keys
    global citizen_card
    global rsa_server
    global rsa_client
    global server_address
    options = []
    if not connected:
        options = ["Join croupier","Exit"]
    else:
        options = ["Leave croupier", "Create game table", "Join game table","List all existing game tables","List all connected players",'List Game History',"Exit"]
    cli = interface_main_menu(options)
    selected_option = cli.launch()

    #Dealing with choices
    opt = options.index(selected_option)
    if opt == len(options)-1:
        exit(0)
    else:
        clear_screen()
    if not connected and opt == 0:
        try:
            sock = None
            while not sock:
                citizen_card = None
                cli = interface_login_method()
                selected_option = cli.launch()
                clear_screen()
                if selected_option == 'Username':
                    cli = interface_choose_playerid()
                    player_id = cli.launch()
                    clear_screen()
                elif selected_option == 'Citizen Card':
                    citizen_card = CitizenCard()
                    player_id = citizen_card.fullnames[0]

                sock, rsa_server, rsa_client = join_croupier(server_address,player_id,citizen_card)
                if sock == 'ERROR':
                    print('ERROR:%s'%(rsa_server))
                    sock = None
            print('Welcome '+str(player_id))
            connected = True
        except ConnectionRefusedError:
            print('The server is not online!')
    elif connected and opt == 0:
        leave_croupier(sock)
        citizen_card = None
        connected = False
    elif connected and opt == 1:
        create_game(sock,rsa_server,rsa_client)
        wait_in_lobby_loop(sock)
        print('Game has been created with success!')
    elif connected and opt == 2:
        #Lists all existing games for the user to choose
        games = list(filter(lambda x : len(x['players']) < 4,get_all_games(sock,rsa_server,rsa_client)))
        if games != []:
            cli = interface_choose_game(games)
            selected_game = int(cli.launch().split(' | ')[0])
            clear_screen()
            join_game(sock,selected_game,rsa_server,rsa_client)
            wait_in_lobby_loop(sock)
        else:
            print('There are currently no available games to join')
    elif connected and opt == 3:
        list_games(sock,rsa_server,rsa_client)
    elif connected and opt == 4:
        list_players(sock,rsa_server,rsa_client)
    elif connected and opt == 5:
        list_game_history(sock,rsa_server,rsa_client)
    else:
        print('Invalid input. Please choose a valid option!')

# Waits for all players to join the game
def wait_in_lobby_loop(sock):
    global connected
    global player_id
    global player_keys
    global citizen_card
    global rsa_server
    global rsa_client
    while True:
        players = wait_in_lobby(sock,rsa_server,rsa_client)
        clear_screen()
        print_current_lobby_players(players,player_id)
        if len(players) == 4:
            #Ask if the user agrees to play with the other players
            cli = interface_accept_players()
            opt = cli.launch()
            if opt == 'Yes':
                cipher_algorithm = None
                cipher_mode = None
                sorted_players = sorted(players)
                #You will choose the security algorithm and modes
                if player_id == sorted_players[0]:
                    cli = interface_choose_cipher_algorithm()
                    cipher_algorithm = cli.launch()
                    cli = interface_choose_cipher_mode()
                    cipher_mode = cli.launch()
                player_keys,encryption_settings = notify_server_players_accepted(sock,rsa_server,rsa_client,players,player_id,cipher_algorithm,cipher_mode)
                print(player_id,' has accepted to play with players')
                data = play_game_server(sock,rsa_server,rsa_client)
                if data['status'] == 'OK':
                    r = play_game(sock,rsa_server,rsa_client,player_keys,player_id,players,encryption_settings)
                    if r != 'CHEATING_GAME_OVER':
                        game_result = leave_lobby(sock,rsa_server,rsa_client)
                        game_accounting(sock,rsa_server,rsa_client,game_result,citizen_card)
                        print('CLEAN EXIT FOR PLAYER %s'%player_id)
                    else:
                        print('EXITING WITH STATUS ',r)
                    return
                else:
                    clear_screen()
                    return
            else:
                leave_lobby(sock,rsa_server,rsa_client)
                clear_screen()
                return
        else:
            print_waiting_buffer(players)
        time.sleep(1)

def list_game_history(sock,rsa_server,rsa_client):
    game_list = get_game_history(sock,rsa_server,rsa_client)
    print_game_history(game_list)

def list_players(sock,rsa_server,rsa_client):
    player_list = get_all_players(sock,rsa_server,rsa_client)
    print_player_list(player_list)

def list_games(sock,rsa_server,rsa_client):
    games = get_all_games(sock,rsa_server,rsa_client)
    print_game_list(games)


# Create a TCP/IP socket
server_address = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
print('Server IP: %s'%server_address)
connected = False
player_id = None
#####Security keys#####
#Keys from the other 3 players
player_keys = None
#citizen card variable
citizen_card = None

rsa_server = None
rsa_client = None

clear_screen()
#Interacts with the user
while True:
    main_menu()

