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
def insert_list(tuple, list):
    flag = 0
    if len(list) == 0:
        list.append(tuple)
        flag = 1
    elif list[len(list)-1][0].dport < tuple[0].dport:
        list.append(tuple)
        flag = 1
    else:
        for i in range(len(list)):
            if list[i][0].dport >= tuple[0].dport:
                list.insert(i, tuple)
                flag = 1
                break
    if flag == 0:
        print "insert_list: error"

def insert_hash(tuple, hash):
    l = [tuple]
    flag = 0
    if len(hash) == 0:
        hash.append(l)
        flag = 1
    elif hash[len(hash)-1][0][0].dport < tuple[0].dport:
        hash.append(l)
        flag = 1
    else:
        for i in range(len(hash)):
            if hash[i][0][0].dport == tuple[0].dport:
                hash[i].append(tuple)
                flag = 1
                break
            elif hash[i][0][0].dport > tuple[0].dport:
                hash.insert(i, l)
                flag =1
                break
    if flag == 0:
        print "insert_hash: error"

def count_hash(hash):
    count = 0
    for i in hash:
        for j in i:
            count += 1

    print count

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

    tcp_list = []
    udp_list = []
    tcp_hash = []
    udp_hash = []

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
            tcp_tuple = (tcp, timestamp)
            insert_list(tcp_tuple, tcp_list)
            insert_hash(tcp_tuple, tcp_hash)
            
        elif ip.p==dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            udp_tuple = (udp, timestamp)
            insert_list(udp_tuple, udp_list)
            insert_hash(udp_tuple, udp_hash)
            
        else:
            print "Bad packet"  

    count_hash(tcp_hash)
    count_hash(udp_hash)

# execute a main function in Python
if __name__ == "__main__":
    main()
