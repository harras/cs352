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

# add your own function/class/method defines here.

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

    count = 0

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
            tcp_tuple = (timestamp, tcp)
            time_insert(tcp_tuple, tcp_time_list)
            port_insert(tcp, tcp_port_list)

        elif ip.p==dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            udp_tuple = (timestamp, udp)
            time_insert(udp_tuple, udp_time_list)
            port_insert(udp, udp_port_list)

        else:
            print "Bad packet"  

        count += 1

    print len(tcp_time_list)
    print len(tcp_port_list)
    print len(udp_time_list)
    print len(udp_port_list)
    print count
    
# Custom helper function
# Uses a packet tuple, where tuple[0] is the timestamp of the packet, and tuple[1] is the object
def time_insert(tuple, list):
    if len(list) == 0 or tuple[0] >= list[len(list)-1][0]:
        list.append(tuple)
    else:
        for i in range(len(list)):
            if tuple[0] <= list[i][0] and len(tuple[1].data) > 0:
                list.insert(i, tuple)
                break
            

def port_insert(object, list):
    if len(list) == 0 or object.dport >= list[len(list)-1].dport:
        list.append(object)
    else:
        for i in range(len(list)):
            if object.dport <= list[i].dport and len(object.data) > 0:
                list.insert(i, object)
                break



# execute a main function in Python
if __name__ == "__main__":
    main()
