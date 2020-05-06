import socket
from general import *
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.tcp import TCP
from networking.pcap import Pcap
#import time
import sys

ip_list = []
ip_list2 = []

def main():
    pcap = Pcap('packetCapture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    a = 0
    count = 0
    counter=0
    print('Source IP \t Destination IP \t Source Port \t Destination Port \t Protocol')
    while True:
        
        raw_data, addr = conn.recvfrom(65535)
        pcap.write(raw_data)
        eth = Ethernet(raw_data)
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            # TCP
            if count<=300 and counter<=50:
                if ipv4.proto == 6:
                    tcp = TCP(ipv4.data)

                    print('{} \t  {} \t\t - {} \t\t - {} \t\t {}'.format(ipv4.src,ipv4.target,tcp.src_port,tcp.dest_port,ipv4.proto))
            #         print('RST'+str(tcp.flag_rst),tcp.flag_syn)
                    if tcp.flag_syn ==0 and tcp.flag_ack == 1:
                        count = count+1

                    if tcp.flag_rst == 1:
                        if(len(ip_list)<100):
                            ip_list.append(ipv4.src)
                       # print(ip_list)
                        if tcp.flag_syn == 1:
                            if(len(ip_list2)<100):
                                ip_list2.append(ipv4.src)
                        #print(ip_list2)
                    #time.sleep(5)
                    for i in ip_list2:
                        if i in ip_list:
                            counter = counter+1
                        else:
                            pass
                    #print(counter)       
                    # if(counter>50):
                    #     print('Beyond Threshold')
                    #     sys.exit()
                    # else:
                    #     pass
            else:
                print('Warning:SYN Flood Attack Detected')
                sys.exit()

    pcap.close()


main()
