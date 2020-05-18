               _                     
            __| |___  ___ __ _ _ __  
           / _` / __|/ __/ _` | '_ \ 
          | (_| \__ \ (_| (_| | | | |
           \__,_|___/\___\__,_|_| |_|
                                     

	# coded By OMAR EL HADIDI  - @O_hadidi
Usage: dscan.py [option] {target}

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p  , --port=         ADD A PORT , OR MULTIPLE PORTS SEPARATED BY ','
  -r  , --range=        ADD A PORT RANGE , SEPARATED BY '-'
  -O  File Name , --out= File Name 
                        Print output in a file

  network discovery :
    dscan.py -1 192.168.1.1

    -0  IP, --arp-scan= IP
                        ARP MODE [NETWORK ADDRESS]
    -1, --icmp-ping     ICMP MODE
    -2, --udp-ping      UDP MODE
    -3, --tcp-ack       TCP WITH ACK FLAG SET
    -4, --tcp-syn       TCP WITH SYN FLAG SET

  PORT SCAN :
    dscan [option] {ports} [Scan_option] [HOST]

    -T, --tcp           tcp connect scan
    -S, --syn           Syn scan
    -F, --fin           fin scan
    -N, --null          null scan
    -A, --ack           ack scan
    -U, --udp           udp scan
    -X, --xmas          xmas scan
    -M, --Maimon        Maimon scan

  EXAMPLES :
    dscan.py -p 80 -S 192.168.1.1

IF NO PORT SPECIFIED THE FIRST 1024 PORTS WILL BE SCANNED
