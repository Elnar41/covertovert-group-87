import re
import time
import random
from scapy.all import DNS, DNSQR, IP, UDP
from scapy.all import sniff
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    All the parameters are read from config.json
    """

    def __init__(self):
        super().__init__()
    

    def send(self, log_file_name, domain, count_time):
        """
            This function sends packets via DNS to transmit a covert binary message. The process begins by generating a random 
            binary message, which is also logged using a function from the CovertChannelBase class. 

            First, a "dump packet" is sent to initialize the communication. This allows the receiver to start a timer 
            for "last_packet_time" (set to the current time). 

            The binary message is then iterated over, and for each bit:
            1. A DNS query packet is created (though the packet itself is not used for encoding).
            2. If the bit is '0', the function introduces a short delay (ranging from 0.001 ms to 0.01 ms).
            3. If the bit is '1', the function introduces a longer delay (ranging from 1.1 seconds to 3 seconds). 

            The delay values are chosen to accommodate potential network delays. Even in cases of network-induced latency, the 
            receiver should be able to distinguish between '0' and '1'. After the delay, the packet is sent.

            This process continues until all bits of the binary message are transmitted successfully.
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        dump_package = IP(dst="172.18.0.3") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        super().send(dump_package)
        for bit in binary_message:
            packet = IP(dst="172.18.0.3") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            if bit == '0':
                time.sleep(random.uniform(1, count_time / 100) / 1000)  # Shorter delay for 0
            elif bit == '1':
                time.sleep(random.uniform(count_time + 100, count_time * 3) / 1000)  # Longer delay for 1

            super().send(packet)


    def receive(self, domain, count_time, log_file_name, received_message, counter, last_packet_time):
            """
            This function receives packets via DNS to reconstruct a covert binary message. 
            It uses the Scapy 'sniff' function to capture DNS query packets and process 
            them based on their inter-arrival times to decode the binary message.

            Parameters:
            - parameter1: A string representing the domain or keyword to filter the packets.
            - parameter2: A threshold value (in seconds) to distinguish between binary '0' and '1'.
            - log_file_name: Name of the log file to store the decoded message.
            """

            def process_packet(packet):
                """
                This inner function processes each captured packet and determines if it should 
                be treated as a '0' or '1' based on the inter-arrival time.
                
                - Updates the binary message.
                - Converts 8 bits into a character and prints it immediately.
                - Stops sniffing if the character '.' is received, indicating the end of the message.
                """
                nonlocal last_packet_time, received_message, counter
                if DNS in packet and packet[DNS].qd and domain in packet[DNS].qd.qname.decode():
                    current_time = time.time()  # Capture the current time for this packet
                    if last_packet_time != -1:
                        # Calculate inter-arrival time
                        inter_arrival_time = (current_time - last_packet_time) * 1000

                        if inter_arrival_time < count_time:  # Short delay indicates '0'
                            received_message += '0'
                        else:  # Longer delay indicates '1'
                            received_message += '1'
                        
                        counter += 1
                        if counter == 8:  # Once 8 bits are collected
                            char = self.convert_eight_bits_to_character(received_message[-8:])
                            print(char) #For tracking changes
                            counter = 0  # Reset counter for the next 8 bits
                            if char == ".":  # Stop sniffing if the end marker is reached
                                return True

                    # Update the last packet time for the next packet
                    last_packet_time = current_time
                return False

            # Start sniffing for packets that match the specified filter
            sniff(filter=f"udp port 53 and host 172.18.0.3", stop_filter=process_packet)

            if not received_message:
                print("No packets captured.")  # Notify if no packets were received
            else:
                # Decode the full binary message into a human-readable format
                decoded_message = "".join(
                    self.convert_eight_bits_to_character(received_message[i:i + 8])
                    for i in range(0, len(received_message), 8)
                )

                # Log the decoded message for record-keeping
                self.log_message(decoded_message, log_file_name)

