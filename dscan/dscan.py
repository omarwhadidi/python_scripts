import scapy.all as scapy
import pyfiglet, termcolor, colorama
import time, datetime, sys
import optparse

final_time = ""
finflag = 0x1
synflag = 0x2
rstflag = 0x4
pushflag = 0x8
ackflag = 0x10
synack = 0x12
rstack = 0x14
urgflag = 0x20


def get_arguments():
    parser = optparse.OptionParser(usage="dscan.py [option] {target}", version=1.0)
    parser.add_option("-p", "--port", dest="port", help="ADD A PORT , OR MULTIPLE PORTS SEPARATED BY ','", metavar=" ")
    parser.add_option("-r", "--range", dest="portrange", help="ADD A PORT RANGE , SEPARATED BY '-' ", metavar=" ")
    parser.add_option("-O", "--out", dest="outfile", help="Print output in a file ", metavar=" File Name ")
    parser.epilog = "IF NO PORT SPECIFIED THE FIRST 1024 PORTS WILL BE SCANNED"
    ping_arg = optparse.OptionGroup(parser, 'network discovery ', 'dscan.py -1 192.168.1.1 ', )
    ping_arg.add_option("-0", "--arp-scan", dest="arp", help="ARP MODE [NETWORK ADDRESS]", metavar=" IP")
    ping_arg.add_option("-1", "--icmp-ping", action="store_true", dest="ping", help="ICMP MODE")
    ping_arg.add_option("-2", "--udp-ping", action="store_true", dest="udp_scan", help="UDP MODE")
    ping_arg.add_option("-3", "--tcp-ack", action="store_true", dest="ack_scan", help="TCP WITH ACK FLAG SET ")
    ping_arg.add_option("-4", "--tcp-syn", action="store_true", dest="syn_scan", help="TCP WITH SYN FLAG SET")
    parser.add_option_group(ping_arg)

    portscan_arg = optparse.OptionGroup(parser, 'PORT SCAN ', 'dscan [option] {ports} [Scan_option] [HOST]', )
    portscan_arg.add_option("-T", "--tcp", action="store_true", dest="full", help="tcp connect scan",
                            metavar="port[s] ")
    portscan_arg.add_option("-S", "--syn", action="store_true", dest="syn", help="Syn scan", metavar="port[s]")
    portscan_arg.add_option("-F", "--fin", action="store_true", dest="fin", help="fin scan", metavar="port[s]")
    portscan_arg.add_option("-N", "--null", action="store_true", dest="null", help="null scan", metavar="port[s]")
    portscan_arg.add_option("-A", "--ack", action="store_true", dest="ack", help="ack scan", metavar="port[s]")
    portscan_arg.add_option("-U", "--udp", action="store_true", dest="udp", help="udp scan", metavar="port[s]")
    portscan_arg.add_option("-X", "--xmas", action="store_true", dest="xmas", help="xmas scan", metavar="port[s]")
    portscan_arg.add_option("-M", "--Maimon", action="store_true", dest="maimon", help="Maimon scan", metavar="port[s]")
    parser.add_option_group(portscan_arg)

    examples = optparse.OptionGroup(parser, 'EXAMPLES ', 'dscan.py -p 80 -S 192.168.1.1', )
    parser.add_option_group(examples)

    (options, arguments) = parser.parse_args()
    if (options.ping or options.arp or options.udp_scan or options.udp_scan or options.udp_scan) and (
            options.port or options.portrange or options.maimon or options.xmas or options.udp or options.ack or options.syn or options.fin or options.full):
        parser.error("Bad Arguments please specify port scan or network scan , use --help for more info")
    if not options.ping and not options.udp_scan and not options.ack_scan and not options.syn_scan and not options.arp:
        if not options.port and not options.portrange:
            parser.error("please specify a port , use --help for more info")
    return options, arguments


def syn_scan(target_ip, target_port):
    try:
        src_port = scapy.RandShort()
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags="S")
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / tcp_packet
        response = scapy.sr1(packet_sent, timeout=0.5, verbose=False)
        flag = response.getlayer(scapy.TCP).flags
        if flag == synack:
            result = "port {} :   open ".format(target_port)
        elif flag == rstack:
            result = False
        connection_close = scapy.IP(dst=target_ip) / scapy.TCP(sport=134, dport=target_port, flags="R")
        scapy.send(connection_close, verbose=False)
        return result
    except AttributeError:
        return False
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


def tcp_scan(target_ip, target_port):
    try:
        src_port = scapy.RandShort()
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags="S")
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / tcp_packet
        response = scapy.sr1(packet_sent, timeout=0.5, verbose=False)
        flag = response.getlayer(scapy.TCP).flags
        if flag == synack:
            result = "port {} :   open  ".format(target_port)
        elif flag == rstack:
            result = False
        connection_close = scapy.IP(dst=target_ip) / scapy.TCP(sport=134, dport=target_port, flags="AR")
        scapy.send(connection_close, verbose=False)
        return result
    except AttributeError:
        return False
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


def xnf_scan(target_ip, target_port, flags):  # (xmas , fin , null )
    # does'nt work for windows os
    try:
        result = ""
        src_port = scapy.RandShort()
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags=flags)
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / tcp_packet
        response = scapy.sr1(packet_sent, timeout=0.5, verbose=False)
        flag = response.getlayer(scapy.TCP).flags
        if flag == rstack:
            result = False
        elif response.getlayer(scapy.ICMP):
            if int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) in [1, 2, 3, 9,
                                                                                                            10, 13]:
                result = "port {} :   Filtered  ".format(target_port)

        return result
    except AttributeError:
        return "port {} :   OPEN | Filtered".format(target_port)
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


def ack_scan(target_ip, target_port, flags):
    # does'nt work for windows os
    try:
        result = ""
        src_port = scapy.RandShort()
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags=flags)
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / tcp_packet
        response = scapy.sr1(packet_sent, timeout=0.5, verbose=False)
        flag = response.getlayer(scapy.TCP).flags
        if flag == rstflag:
            result = "port {} :   Unfiltered ".format(target_port)
        elif response.getlayer(scapy.ICMP):
            if int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) in [1, 2, 3, 9,
                                                                                                            10, 13]:
                result = "port {}  :   Filtered ".format(target_port)

        return result
    except AttributeError:
        return "port {} :   Filtered ".format(target_port)
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


def maimon_scan(target_ip, target_port, flags):
    # does'nt work for windows os
    try:
        result = ""
        src_port = scapy.RandShort()
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags=flags)
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / tcp_packet
        response = scapy.sr1(packet_sent, timeout=0.5, verbose=False)
        flag = response.getlayer(scapy.TCP).flags
        if flag == rstflag:
            result = "port {} :   closed ".format(target_port)
        elif response.getlayer(scapy.ICMP):
            if int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) in [1, 2, 3, 9,
                                                                                                            10, 13]:
                result = "port {}  :   Filtered ".format(target_port)

        return result
    except AttributeError:
        return "port {} :   OPEN | Filtered ".format(target_port)
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


def udp_scan(target_ip, target_port):
    try:
        udp_packet = scapy.UDP(dport=target_port)
        ip_packet = scapy.IP(dst=target_ip)
        packet_sent = ip_packet / udp_packet
        response = scapy.sr1(packet_sent, timeout=5, verbose=False)
        if response.haslayer(scapy.UDP):
            return "port {} :   OPEN  ".format(target_port)
        elif response.haslayer(scapy.ICMP):
            if int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) == 3:
                return False
            elif int(response.getlayer(scapy.ICMP).type) == 3 and int(response.getlayer(scapy.ICMP).code) in [1, 2, 9,
                                                                                                              10, 13]:
                return "port {} :   Filtered  ".format(target_port)

    except AttributeError:
        retrans = []
        for count in range(0, 3):
            retrans.append(scapy.sr1(packet_sent, timeout=2, verbose=False))
        for item in retrans:
            try:
                if item.haslayer(scapy.UDP):
                    udp_scan(target_ip, target_port)
            except AttributeError:
                return "port {} :   OPEN | Filtered ".format(target_port)
    except KeyboardInterrupt:
        print("[-] ctr+c ... Quiting")
        sys.exit(1)


# def idle_scan () :
# def mansion_scan() :
####################################### HOST DISCOVERY FUNCTIONS

def arp_scan(host):
    try:
        arp_request = scapy.ARP(pdst=host)
        broadcast_ethernet_packet = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
        packet = broadcast_ethernet_packet / arp_request
        answered_list = scapy.srp(packet, timeout=1, verbose=False)[0]
        unanswered_list = scapy.srp(packet, timeout=1, verbose=False)[1]

        hosts_lists = []
        for host in answered_list:
            hosts = {"ip": host[1].psrc,
                     "mac": host[1].hwsrc}  # answered_list contains 2 lists requests hosts[0] and responses hosts[1]
            hosts_lists.append(hosts)

        return hosts_lists
    except KeyboardInterrupt as err:
        print("[-] ctr+c ... Quiting")


def ping(ip):
    icmp_packet = scapy.ICMP()
    ip = scapy.IP(dst=ip)
    ping = ip / icmp_packet
    result = scapy.sr1(ping, timeout=0.5, verbose=0)
    if result == None:
        return False
    else:
        return True


def tcp_syn(ip):
    icmp_packet = scapy.TCP(dport=80, window=1024, flags="S")
    ip = scapy.IP(dst=ip)
    ping = ip / icmp_packet
    result = scapy.sr1(ping, timeout=0.5, verbose=0)
    if result == None:
        return False
    else:
        return True


def tcp_ack(ip):
    icmp_packet = scapy.TCP(dport=80, flags="A")
    ip = scapy.IP(dst=ip)
    ping = ip / icmp_packet
    result = scapy.sr1(ping, timeout=0.5, verbose=0)
    if result == None:
        return False
    else:
        return True


def udp(ip):
    udp_packet = scapy.UDP(dport=40125)
    ip = scapy.IP(dst=ip)
    ping = ip / udp_packet
    result = scapy.sr1(ping, timeout=1, verbose=0)
    if result == None:
        return False
    else:
        return True


scan_result = []


def get_result():
    global scan_result
    get_arguments()
    options, arguments = get_arguments()
    if options.arp:
        list_scan = arp_scan(options.arp)
        scan_result.append("LIVE HOSTS\t\t\tMAC ADDRESS\n")
        for clients in list_scan:
            scan_result.append("HOST " + clients["ip"] + " is up           " + clients["mac"])
    if options.udp_scan:
        try:
            for host in arguments:
                result_scan = udp(host)
                if result_scan:
                    scan_result.append("HOST {} : is up".format(host))
        except KeyboardInterrupt:
            print("[-] ctr+c ... Quiting")
            sys.exit(1)
    if options.ping:
        try:
            for host in arguments:
                result_scan = ping(host)
                if result_scan:
                    scan_result.append("HOST {} : is up".format(host))
        except KeyboardInterrupt:
            print("[-] ctr+c ... Quiting")
            sys.exit(1)
    if options.ack_scan:
        try:
            for host in arguments:
                result_scan = tcp_ack(host)
                if result_scan:
                    scan_result.append("HOST {} : is up".format(host))
        except KeyboardInterrupt:
            print("[-] ctr+c ... Quiting")
            sys.exit(1)
    if options.syn_scan:
        try:
            for host in arguments:
                result_scan = tcp_syn(host)
                if result_scan:
                    scan_result.append("HOST {} : is up".format(host))
        except KeyboardInterrupt:
            print("[-] ctr+c ... Quiting")
            sys.exit(1)

    if options.portrange:
        scan_result.append("PORT\t    STATUS")
        range_striped = options.portrange.strip()
        range_ports = range_striped.split("-")
        for i in range(int(range_ports[0]), int(range_ports[1]) + 1):
            if options.udp:
                result_udp_scan = udp_scan(arguments[0], int(i))
                if result_udp_scan:
                    scan_result.append(result_udp_scan)

            if options.full:
                result_tcp_scan = tcp_scan(arguments[0], int(i))
                if result_tcp_scan:
                    scan_result.append(result_tcp_scan)

            if options.syn:
                result_syn_scan = syn_scan(arguments[0], int(i))
                if result_syn_scan:
                    scan_result.append(result_syn_scan)

            if options.fin:
                result_fin_scan = xnf_scan(arguments[0], int(i), "F")
                if result_fin_scan:
                    scan_result.append(result_fin_scan)

            if options.ack:
                result_ack_scan = ack_scan(arguments[0], int(i), "A")
                if result_ack_scan:
                    scan_result.append(result_ack_scan)

            if options.xmas:
                result_xmas_scan = xnf_scan(arguments[0], int(i), "PFU")
                if result_xmas_scan:
                    scan_result.append(result_xmas_scan)

            if options.null:
                result_null_scan = xnf_scan(arguments[0], int(i), "")
                if result_null_scan:
                    scan_result.append(result_null_scan)

            if options.maimon:
                result_maimon_scan = maimon_scan(arguments[0], int(i), "FA")
                if result_maimon_scan:
                    scan_result.append(result_maimon_scan)
    elif options.port:
        scan_result.append("PORT\t    STATUS")
        striped = options.port.strip()
        ports = striped.split(",")
        for i in range(0, len(ports)):
            if options.udp:
                result_udp_scan = udp_scan(arguments[0], int(ports[i]))
                if result_udp_scan:
                    scan_result.append(result_udp_scan)

            if options.full:
                result_tcp_scan = tcp_scan(arguments[0], int(ports[i]))
                if result_tcp_scan:
                    scan_result.append(result_tcp_scan)

            if options.syn:
                result_syn_scan = syn_scan(arguments[0], int(ports[i]))
                if result_syn_scan:
                    scan_result.append(result_syn_scan)

            if options.fin:
                result_fin_scan = xnf_scan(arguments[0], int(ports[i]), "F")
                if result_fin_scan:
                    scan_result.append(result_fin_scan)

            if options.ack:
                result_ack_scan = ack_scan(arguments[0], int(ports[i]), "A")
                if result_ack_scan:
                    scan_result.append(result_ack_scan)

            if options.xmas:
                result_xmas_scan = xnf_scan(arguments[0], int(ports[i]), "PFU")
                if result_xmas_scan:
                    scan_result.append(result_xmas_scan)

            if options.null:
                result_null_scan = xnf_scan(arguments[0], int(ports[i]), "")
                if result_null_scan:
                    scan_result.append(result_null_scan)
            if options.maimon:
                result_maimon_scan = maimon_scan(arguments[0], int(ports[i]), "FA")
                if result_maimon_scan:
                    scan_result.append(result_maimon_scan)

    return scan_result


def print_result(result):
    print("Starting Dscan 1.0  at " + str(datetime.datetime.now()) + " (GMT+2)")
    print("--------------------------------------------------------------------")
    options, arguments = get_arguments()
    if options.outfile:
        with open(options.outfile, "w") as file:
            file.write("Starting Dscan 1.0  at " + str(datetime.datetime.now()) + " (GMT+2)\n")
            file.write("--------------------------------------------------------------------\n")
            for i in result:
                file.write(i + "\n")
            file.write("[+]Time taken = " + final_time[0:5] + " seconds")
        print("[+] Result saved in {} \n".format(options.outfile))
    for i in result:
        print(i)


def main():
    banner = pyfiglet.figlet_format("          dscan")
    colorama.init()
    print(termcolor.colored(banner, color="red"))
    termcolor.cprint("\t# coded By OMAR EL HADIDI  - @O_hadidi", "magenta")

    time1 = time.time()
    final = get_result()
    time2 = time.time()
    global final_time
    final_time = str(time2 - time1)
    print_result(final)

    print("\n\n[+]Time taken = " + final_time[0:5] + " seconds")


main()
