#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'r'))

    # this main loop reads the packets one at a time from the pcap file
    counter = 0
    for timestamp, packet in input_data:
        counter += 1
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        try:
            if ip.p==dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
            else:
                tcp = None

            # Generate IP address dict
            addr = inet_to_str(ip.src)
            if addr in list_of_ips:
                list_of_ips[addr] += 1
            else:
                list_of_ips[addr] = 1 

            # Generate TCP port dict
            port = str(tcp.dport)
            if port in list_of_tcp_ports:
                list_of_tcp_ports[port] += 1
            else:
                list_of_tcp_ports[port] = 1

            # Generate IP:TCP port pair dict
            addr_port = addr+':'+port
            if addr_port in list_of_ip_tcp_ports:
                list_of_ip_tcp_ports[addr_port] += 1
            else:
                list_of_ip_tcp_ports[addr_port] = 1

        except AttributeError:
            pass

    # Generating ordered dicts from previously generated dicts
    sorted_ips = OrderedDict(sorted(list_of_ips.items(), key=lambda x: x[1], reverse=True))
    sorted_tcp_ports = OrderedDict(sorted(list_of_tcp_ports.items(), key=lambda x: x[1], reverse=True))
    sorted_ip_tcp_ports = OrderedDict(sorted(list_of_ip_tcp_ports.items(), key=lambda x: x[1], reverse=True))

    # Stdout statements
    print "CS 352 Wireshark, part 1"
    print "Total number of packets, " + str(counter)
    print "Source IP addresse, count"
    for _ in sorted_ips:
        print str(_) + ',' + str(sorted_ips[_]) 
    print "Destination TCP ports,count"
    for _ in sorted_tcp_ports:
        print str(_) + ',' + str(sorted_tcp_ports[_])
    print "Source IPs/Destination TCP ports,count"
    for _ in sorted_ip_tcp_ports:
        print str(_) + ',' + str(sorted_ip_tcp_ports[_])  

# execute a main function in Python
if __name__ == "__main__":
    main()    
