#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# Custom helper function
def insert_port_list(tuple, list):
    i = 0
    l = [tuple]
    if len(list) == 0:
        list.append(l)
    # If last entry is less than new entry, add new list...
    elif list[len(list)-1][0][0].dport < tuple[0].dport:
        list.append(l)
    else:
        while(True):
            if i >= len(list):
                break
            elif list[i][0][0].dport < tuple[0].dport:
                i = i+1
            elif list[i][0][0].dport == tuple[0].dport:
                list[i].append(tuple)
                break
            elif list[i][0][0].dport > tuple[0].dport:
                list.insert(i, l)
            else:
                print "FUCK"

def print_ports(list):
    for i in list:
        for j in i:
            print j[0].dport

def print_times(list):
    for i in list:
        print i[1]

def print_port_hashes(list):
    for i in list:
        print i[0][0].dport

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))

    tcp_time_list = []
    tcp_port_list = []
    udp_time_list = []
    udp_port_list = []

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        
        #print timestamp

        eth = dpkt.ethernet.Ethernet(packet)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data

        if ip.p==dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            #print tcp.dport
            tcp_tuple = (tcp, time_string)
            tcp_time_list.append(tcp_tuple)
            insert_port_list(tcp_tuple, tcp_port_list)

        elif ip.p==dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            #print udp.dport
            udp_tuple = (udp, time_string)
            udp_time_list.append(udp_tuple)
            insert_port_list(udp_tuple, udp_port_list)

            
        else:
            print "Bad packet"  

    print_times(tcp_time_list)
    print_ports(tcp_port_list)
    print_times(udp_time_list)
    print_ports(udp_port_list)
    print len(tcp_port_list)
    print len(tcp_time_list)
    print len(udp_port_list)
    print len(udp_time_list)
    #print
   # print_port_hashes(tcp_port_list)



# execute a main function in Python
if __name__ == "__main__":
    main()
