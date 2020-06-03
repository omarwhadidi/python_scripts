#!/usr/bin/env python3
import termcolor
import pyfiglet
import subprocess
import argparse
import re, random
import sys

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')
if is_windows:
    import colorama

    colorama.init()  # windows deserve coloring too xd


#           ==================================== WINDOWS ======================== 
# getmac /v /fo list
# getmac /v

# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\<ID of NIC, e.g. 0001>\NetworkAddress
# reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0004 /v NetworkAddress /d <newmac> /f

def get_arguments():
    parser = argparse.ArgumentParser(usage=termcolor.colored("mac_changer.py [option] " , "green") ,
                                     epilog=termcolor.colored("\nExample:\nmac_changer.py -i eth0 -r " , "magenta"))
    parser._optionals.title = "OPTIONS"
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its MAC Address")
    parser.add_argument("-m", "--mac", dest="mac", help=" New mac Address ")
    parser.add_argument("-r", "--random", action="store_true", dest="rand_mac", help="Random Mac Address ")

    options = parser.parse_args()

    if not options.interface:
        parser.error(termcolor.colored("[-] please specify an interface to change , use --help for more info. " , "red") )
    elif not options.mac  and not options.rand_mac:
        parser.error(termcolor.colored("[-] Please specify a new MAC or choose -r for random MAC, use --help for more info." , "red"))
    return options


def get_mac(interface):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface])
        mac_address_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
        if mac_address_result:
            return mac_address_result.group(0)
        else:
            print("[-] coudn't get a mac address")
    except:
        pass


def mac_change(interface, new_mac):
    subprocess.call("ifconfig " + interface + " down", shell=True)
    subprocess.call("ifconfig " + interface + " hw ether " + new_mac, shell=True)
    subprocess.call("ifconfig " + interface + " up", shell=True)
    print("[+] changing mac address ...")


def random_mac(interface):
    create_random_mac = "02:00:00:%02x:%02x:%02x" % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", create_random_mac])
    subprocess.call(["ifconfig", interface, "up"])
    global RANDOM_MAC
    RANDOM_MAC = create_random_mac
    print("[+] changing mac address ...")


def main():
    print(termcolor.colored(pyfiglet.figlet_format("mac changer"), color='red'))
    
    options = get_arguments()

    interface = options.interface
    new_mac = options.mac

    current_mac = get_mac(options.interface)
    print("current mac is : " + str(current_mac))
    if options.rand_mac:
        random_mac(interface)
        current_mac = get_mac(options.interface)
        if current_mac == RANDOM_MAC:
            print("[+] Mac address was changed to " + str(current_mac))
        else:
            print("[-] Mac address didn't changed , please try again")
    else:
        mac_change(interface, new_mac)
        current_mac = get_mac(options.interface)
        if current_mac == new_mac:
            print("[+] Mac address was changed to " + str(current_mac))
        else:
            print("[-] Mac address didn't changed , please try again")


main()
