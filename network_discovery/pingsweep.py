import optparse
import time
import pyfiglet , termcolor , colorama
import  scapy.all as scapy

def get_arguments() :
    parser = optparse.OptionParser(usage="pingsweep.py [option] {target}", version=1.0 ,epilog='Ex : pingsweep.py -t 192.168.1.0/24')
    parser.add_option("-t" , "--target" , dest="target" , help="scan a target")
    (options , arguments) = parser.parse_args()
    if not options.target :
        parser.error("[-] please specify a target to scan , use --help for more info")
    return options

def scan(host) :
    try :
        arp_request = scapy.ARP(pdst=host)
        broadcast_ethernet_packet = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
        packet = broadcast_ethernet_packet/arp_request                   #combine 2 requests with each others using /
        answered_list = scapy.srp(packet , timeout=1 , verbose=False)[0] #srp=send and receive responce for that packet the response contains 2 lists
        unanswered_list = scapy.srp(packet, timeout=1, verbose=False)[1] #the list for live hosts and list for down hosts (didnt respond)

        hosts_lists = []
        for host in answered_list :
            hosts = {"ip": host[1].psrc , "mac":host[1].hwsrc}            #answered_list contains 2 lists requests hosts[0] and responses hosts[1]
            hosts_lists.append(hosts)

        return hosts_lists
    except KeyboardInterrupt as err :
        print("[-] ctr+c ... Quiting")

def print_result(results_lists):
        print("| IP Address\t | \tMAC ADDRESS")
        print("------------------------------------------")
        for clients in results_lists:
            print("[+] " + clients["ip"] + "       " + clients["mac"])  # print the source ip and mac address of the destination


def main () :
        banner = pyfiglet.figlet_format("ping sweep")
        colorama.init()
        print(termcolor.colored(banner , color='red'))
        options = get_arguments()
        hosts = options.target
        time1= time.time()

        results = scan(hosts)
        print_result(results)

        time2 = time.time()
        final_time = str(time2-time1)
        print("\n[+] scan completed in " + final_time[0:5] + " seconds")
main()