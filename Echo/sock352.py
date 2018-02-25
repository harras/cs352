
# This is the skeleton code of a cs 352 socket
# You must change the code in the pass statements to make the client and server work. 

import socket as ip

class socket:
    
    s = None

    def __init__(self):
        self.s = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
    
    def socket():
        if self.s is None:
            self.__init__()
        return self.s
    
    def bind(self,address):
        self.s.bind(address)
    
    def sendto(self,buffer,address):
        self.s.sendto(buffer,address)

    def recvfrom(self,nbytes):
        return self.s.recvfrom(nbytes)

    def close(self):
        self.s.close()

