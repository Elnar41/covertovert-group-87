import re
from socket import timeout
import string
from tabnanny import verbose
import time
import random
from scapy.all import DNS, DNSQR, IP, UDP
from scapy.all import sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):

    def __init__(self):
        super().__init__()
    

    def send(self, log_file_name, parameter1, parameter2):
    
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        dump_package = IP(dst="172.18.0.3") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=parameter1))
        super().send(dump_package)
        for bit in binary_message:
            packet = IP(dst="172.18.0.3") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=parameter1))
            if bit == '0':
                time.sleep(random.uniform(1, parameter2 / 100) / 1000)  # Shorter delay for 0
            elif bit == '1':
                time.sleep(random.uniform(parameter2 + 100, parameter2 * 3) / 1000)  # Longer delay for 1

            super().send(packet)


    def receive(self, parameter1, parameter2, log_file_name):

        received_message = ""
        counter = 0
        last_packet_time = None

        def process_packet(packet):
            nonlocal last_packet_time, received_message, counter
            if DNS in packet and packet[DNS].qd and parameter1 in packet[DNS].qd.qname.decode():
                current_time = time.time()
                if last_packet_time is not None:
                    inter_arrival_time = (current_time - last_packet_time) * 1000
                    
                    #Add network delay here as well!!
                    if inter_arrival_time < parameter2:
                        received_message += '0'
                    else:
                        received_message += '1'
                    
                    counter += 1
                    if counter == 8:
                        char = self.convert_eight_bits_to_character(received_message[-8:])
                        counter = 0
                        print(char, end="")
                        if char == ".":
                           return True

                last_packet_time = current_time
            return False
       
        sniff(filter=f"udp port 53 and host 172.18.0.3", stop_filter=process_packet)

    
        if not received_message:
            print("No packets captured.")
        else:
            decoded_message = "".join(
                self.convert_eight_bits_to_character(received_message[i:i + 8])
                for i in range(0, len(received_message), 8)
            )
            print(decoded_message)


            # Log the received message
            self.log_message(decoded_message, log_file_name)
