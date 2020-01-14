from bullet import *
from prettytable import PrettyTable

#Graphic attributes
separator = '\n▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬ HEARTS ▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n'
cheating_prompt = 'I Choose to cheat 😈'

def clear_screen():
    print(chr(27) + "[2J")

class MinMaxCheck(Check):
    def __init__(self, min_selects=0, max_selects=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.min_selects = min_selects
        self.max_selects = max_selects
        if max_selects is None:
            self.max_selects = len(self.choices)

    @keyhandler.register(13)
    def accept(self):
        if self.valid():
            return super().accept()

    def valid(self):
        return self.min_selects <= sum(1 for c in self.checked if c) <= self.max_selects

def interface_main_menu(options):
    return Bullet(separator,
            choices = options,
            indent = 0,
            align = 5, 
            margin = 2,
            bullet = "★",
            bullet_color=colors.bright(colors.foreground["yellow"]),
            word_on_switch=colors.bright(colors.foreground["yellow"]),
            background_on_switch=colors.background["cyan"],
            pad_right = 5)

def interface_login_method():
    return Bullet(separator,
                choices = ['Username','Citizen Card'],
                indent = 0,
                align = 5, 
                margin = 2,
                bullet = "★",
                bullet_color=colors.bright(colors.foreground["yellow"]),
                word_on_switch=colors.bright(colors.foreground["yellow"]),
                background_on_switch=colors.background["cyan"],
                pad_right = 5)

def interface_choose_cipher_algorithm():
    return Bullet(separator,
            choices = ['AES', 'Camellia', 'TripleDES', 'CAST5', 'SEED', 'Blowfish', 'IDEA'],
            indent = 0,
            align = 5, 
            margin = 2,
            bullet = "★",
            bullet_color=colors.bright(colors.foreground["yellow"]),
            word_on_switch=colors.bright(colors.foreground["yellow"]),
            background_on_switch=colors.background["cyan"],
            pad_right = 5)

def interface_choose_cipher_mode():
    return Bullet(separator,
            choices = ['CBC', 'OFB', 'CFB'],
            indent = 0,
            align = 5, 
            margin = 2,
            bullet = "★",
            bullet_color=colors.bright(colors.foreground["yellow"]),
            word_on_switch=colors.bright(colors.foreground["yellow"]),
            background_on_switch=colors.background["cyan"],
            pad_right = 5)

def interface_choose_playerid():
    return Input("Choose your player ID: ",
                default = "",
                word_color = colors.foreground["yellow"])

def interface_choose_game(games):
    return Bullet(separator+'\nPlease choose the game you would like to join:',
                choices = list(map(lambda x : str(x['id'])+' | '+str(len(x['players']))+'/4 players | '+('Started' if x['has_started'] else 'Waiting for players'),games)),
                indent = 0,
                shift = 1,
                align = 2, 
                margin = 2,
                bullet = "★",
                bullet_color=colors.bright(colors.foreground["yellow"]),
                word_on_switch=colors.bright(colors.foreground["yellow"]),
                background_on_switch=colors.background["cyan"],
                pad_right = 5)

def interface_accept_players():
    return Bullet(prompt = "Do you accept to play with these players?",
                choices = ['Yes','Back to main menu'], 
                indent = 0,
                shift = 1,
                align = 2, 
                margin = 2,
                bullet = "★",
                bullet_color=colors.bright(colors.foreground["yellow"]),
                word_on_switch=colors.bright(colors.foreground["yellow"]),
                background_on_switch=colors.background["cyan"],
            )

def interface_validate_play():
    return Bullet(prompt = "Was this a valid play?",
                choices = ['Yes','No'], 
                indent = 0,
                shift = 1,
                align = 2, 
                margin = 2,
                bullet = "★",
                bullet_color=colors.bright(colors.foreground["yellow"]),
                word_on_switch=colors.bright(colors.foreground["yellow"]),
                background_on_switch=colors.background["cyan"],
            )

def interface_cheating_reason():
    return Bullet(prompt = "Reason for accusation?",
            choices = ['PLAYED_MY_CARD','PLAYED_CARD_TWICE','RENOUNCE'], 
            indent = 0,
            shift = 1,
            align = 2, 
            margin = 2,
            bullet = "★",
            bullet_color=colors.bright(colors.foreground["yellow"]),
            word_on_switch=colors.bright(colors.foreground["yellow"]),
            background_on_switch=colors.background["cyan"],
        )

def print_current_lobby_players(players,player_id):
    table = PrettyTable(['ID'])
    for p in players:
        table.add_row([p+('(you)' if p==player_id else '')])
    print(table)

def print_waiting_buffer(players):
    print('▬▬▬▬▬▬▬▬▬▬▬▬▬ Waiting for players (%s/4) ▬▬▬▬▬▬▬▬▬▬▬▬' % str(len(players)))

def print_player_list(player_list):
    print('There are %d connected players:' % len(player_list))
    table = PrettyTable(['ID','Game'])
    for p in player_list:
        table.add_row([p['id'], p['game'] if p['game'] != -1 else 'None'])
    print(table)

def print_game_list(games):
    print('There are %d ongoing games.' % len(games))
    table = PrettyTable(['ID', 'Players','Status','State'])
    for game_json in games:
        status = ''
        if game_json['has_started']:
            status = 'Started'
        elif not game_json['has_started'] and len(game_json['players']) == 4:
            status = 'Full'
        else:
            status = 'Waiting for players'
        table.add_row([game_json['id'], str(len(game_json['players']))+'/4',status,game_json['state']])
    print(table)

def print_game_history(game_history):
    print('You have %d games registered in your history:' % len(game_history))
    table = PrettyTable(['Game','Player1','Player2','Player3','Player4'])
    for g in game_history:
        game_list = g['players']
        row = [g['game_id']]
        for i in range(len(game_list)):
            row += ['%s(%s points)'%(game_list[i]['id'][:17],game_list[i]['points'])]
        table.add_row(row)
    print(table)

############## HEARTS #################
def print_cards_on_table(cards,player_id):
    table = PrettyTable(['ID','Card Played','Player turn','Points','Current Suit','Game turn'])
    for p in cards:
        card_played = 'None'
        if p['cardPlayed'] != 0:
            tmp = p['cardPlayed'].split('|')
            if tmp[1] == 'H': tmp[1] = '♥'
            elif tmp[1] == 'D': tmp[1] = '♦'
            elif tmp[1] == 'C': tmp[1] = '♣'
            elif tmp[1] == 'S': tmp[1] = '♠'
            card_played = tmp[0]+tmp[1]
        table.add_row([p['id']+('(you)' if p['id']==player_id else ''), #ID
                        card_played, # Card Played
                        '√' if p['playing'] else '', #Player turn
                        p['points'], #Player points
                        p['currentSuit'], #Current suit
                        p['turn'] #Game turn] #
        ]) 
    print(table)

def print_final_positions(positions):
    pos = ['1st','2nd','3rd','4th']
    table = PrettyTable(['Position','ID','Points'])
    for i in range(len(positions)):
        p = positions[i]
        table.add_row([pos[i],p['id'],p['points']]) 
    print(table)

def interface_discard_cards(hand):
    return MinMaxCheck(prompt='Choose 3 cards to give to your oponnent',
            min_selects = 3,
            max_selects = 3,
            choices = hand,
            indent = 0,
            align = 5, 
            margin = 2,
            check = "√",
            check_color = colors.foreground["red"],
            check_on_switch = colors.foreground["red"],
            word_color = colors.foreground["black"],
            word_on_switch = colors.foreground["black"],
            background_color = colors.background["white"],
            background_on_switch = colors.background["yellow"])

def interface_play_card(hand):
    formatted_hand = []
    for i in range(len(hand)):
        c = hand[i].split('|')
        value = c[0]
        suit = c[1]
        if suit == 'H': suit = '♥'
        elif suit == 'D': suit = '♦'
        elif suit == 'C': suit = '♣'
        elif suit == 'S': suit = '♠'
        formatted_hand += [value+' '+suit]

    cli = Bullet(prompt = "\nChoose a card to play: ",
                choices = formatted_hand+[cheating_prompt], 
                indent = 0,
                shift = 1,
                align = 2, 
                margin = 2,
                bullet = "★",
                bullet_color=colors.bright(colors.foreground["yellow"]),
                word_on_switch=colors.bright(colors.foreground["yellow"]),
                background_on_switch=colors.background["cyan"],
            )
    card = cli.launch()
    if card != cheating_prompt:
        card = card.split(' ')
        if card[1] == '♥': card[1] = 'H'
        elif card[1] == '♦': card[1] = 'D'
        elif card[1] == '♣': card[1] = 'C'
        elif card[1] == '♠': card[1] = 'S'
        card = '|'.join(card)
    return card

def interface_cheat_card():
    return Input("😈 Card to play (ex: 3|C is the 3 of clubs): ",
                indent = 0,
            )