#!/usr/bin/python3
# Program for execute show and configuration commands on cisco devices
# run python3 <name.py> -h
#

import argparse
import getpass
from scrapli import Scrapli
from scrapli.exceptions import ScrapliException


parser = argparse.ArgumentParser(description='Program for execute show and configuration commands on cisco devices')

parser.add_argument('-i', '--ip', type=ascii, action='store',
                    help='IP address devices')
parser.add_argument('-s', '--show', type=ascii, action='store',
                    help='show command for devices example "show clock; show inventory"')
parser.add_argument('-c', '--command', type=ascii, action='store',
                    help='configuration command for devices example "no ntp server 1.1.1.1; ntp server 2.2.2.2"')
parser.add_argument('-u', '--user', type=ascii, action='store',
                    help='login user for devices')
parser.add_argument('-p', '--password', type=ascii, action='store',
                    help='password user for devices')

parser.add_argument('-if', '--ip-file', type=open,
                    help='IP address devices in this file')
parser.add_argument('-sf', '--show-file', type=open,
                    help='show commands in this file')
parser.add_argument('-cf', '--command-file', type=open,
                    help='configuration commands in this file')
parser.add_argument('-uf', '--user-file', type=open,
                    help='login and password for authorization in the file')

parser.add_argument('-t', '--type', choices=['iosxe', 'nxos', 'iosxr'], default='iosxe',
                    help='Type device, default value %(default)s')

parser.add_argument('-n', '--nodisplay', action='store_false',
                    help='do not display IP address and other additional information, only display the result')

## -------------------------------------------------------------------------- ##

def request_user():
    tmpuser = getpass.getuser() 
    user = input("Username [{}]: ".format(tmpuser))
    if (user==''):
        user = tmpuser
    return user


def request_pass():
    pwd = getpass.getpass(prompt='Password: ', stream=None)
    return pwd



def send_show(device, show_commands):
    if type(show_commands) == str:
        show_commands = [show_commands]
    cmd_dict = {}
    with Scrapli(**device) as ssh:
        for cmd in show_commands:
            reply = ssh.send_command(cmd)
            cmd_dict[cmd] = reply.result
    return cmd_dict


def send_cfg(device, cfg_commands, strict=False):
    output = ""
    if type(cfg_commands) == str:
        cfg_commands = [cfg_commands]
    try:
        with Scrapli(**device) as ssh:
            reply = ssh.send_configs(cfg_commands, stop_on_failed=strict)
            for cmd_reply in reply:
                if cmd_reply.failed:
                    print(f"При выполнении команды возникла ошибка:\n{reply.result}\n")
            output = reply.result
    except ScrapliException as error:
        print(error, device["host"])
    return output


def print_result (resultf):
    if ( args.nodisplay ):
        print()
        print("Host: ",args.ip.strip("'"))
    for cmd, cmdresult in resultf.items():
        print()
        if ( args.nodisplay ):
            print ("Show command: ",cmd)
            print()
        print (cmdresult)




if __name__ == '__main__':

    ## -------------------------------------------------------------------------- ##
    ## Блок проверки аргументов командной строки
    args = parser.parse_args()
        
    #if ( args.nodisplay ):
    #    print (args) ## test print args 
    
    if ( args.user is None and args.user_file is None ):
        args.user=request_user()
        args.password=request_pass()
    elif ( args.user and args.password is None ):
        args.password=request_pass()
    elif ( args.user and args.password and args.user_file):
        if ( args.nodisplay): print ("Use login: %s" %args.user, ", ignore option -uf " )
    elif ( args.user_file ):
        print ()
        print ("Check login and password in file {}".format( args.user_file ))

    args.type = "cisco_"+args.type
    
    currentdevice = { "host": args.ip.strip("'"),
           "auth_username": args.user.strip("'"),
           "auth_password": args.password.strip("'"),
           "auth_secondary": args.password.strip("'"),
           "auth_strict_key": False,
           "platform": args.type,
           "transport_options": {"open_cmd": ["-o", "KexAlgorithms=+diffie-hellman-group14-sha1", "-o", "Ciphers=+aes256-cbc"]},
           "ssh_config_file": False
         }


    ## -------------------------------------------------------------------------- ##
    ## Блок выполнения аргумента show 
    

    if ( args.show ):
        showcommands = (args.show.strip("'|\"").split(";"))
        result = send_show(currentdevice, showcommands)
        print_result (result)

    ## -------------------------------------------------------------------------- ##
    ## Блок выполнения аргумента command


    if ( args.command ):
        confcommands = (args.command.strip("'|\"").split(";"))
        #print (confcommands) 

        result = send_cfg(currentdevice, confcommands)
        print (result)

