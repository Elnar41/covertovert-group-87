import string
import time
import random
from scapy.all import DNS, DNSQR, IP, UDP
from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
    Implements a covert timing channel that exploits packet inter-arrival times using DNS queries.
    """
    def __init__(self):
        super().__init__()

    def send(self, log_file_name, parameter1, parameter2):
        """
        - Creates a random binary message and sends it via DNS queries.
        - Each bit is encoded using packet inter-arrival times.
        - A dot (.) character signifies the end of communication.

        Args:
        - log_file_name: File name for logging the generated message.
        - parameter1: Base domain for DNS queries.
        - parameter2: Maximum delay in milliseconds for inter-arrival timing.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        # Append the stopping character (dot) in binary form
        binary_message += self.convert_string_message_to_binary(".")

        for bit in binary_message:
            # Construct DNS query packet
            domain = f"{bit}.{parameter1}"
            packet = IP(dst="8.8.8.8") / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
            
            # Use the base class's send function
            super().send(packet)

            # Add delay based on the bit (timing-based encoding)
            if bit == '0':
                time.sleep(random.uniform(1, parameter2 / 2) / 1000)  # Shorter delay for 0
            elif bit == '1':
                time.sleep(random.uniform(parameter2 / 2, parameter2) / 1000)  # Longer delay for 1

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Decodes the binary message received through inter-arrival timing of DNS packets.
        - Stops decoding upon encountering the stopping character (dot).

        Args:
        - parameter1: Base domain for DNS queries.
        - parameter2: Threshold in milliseconds to differentiate between 0 and 1.
        - parameter3: Timeout in seconds to wait for packets.
        - log_file_name: File name for logging the received message.
        """
        from scapy.all import sniff

        received_message = ""
        last_packet_time = None

        def process_packet(packet):
            nonlocal last_packet_time, received_message
            if DNS in packet and packet[DNS].qd and parameter1 in packet[DNS].qd.qname.decode():
                current_time = time.time()
                if last_packet_time is not None:
                    # Calculate inter-arrival time
                    inter_arrival_time = (current_time - last_packet_time) * 1000  # Convert to ms

                    # Decode bit based on inter-arrival time
                    if inter_arrival_time < parameter2:
                        received_message += '0'
                    else:
                        received_message += '1'

                    # Check if stopping character (dot) is decoded
                    if len(received_message) >= 8:
                        char = self.convert_eight_bits_to_character(received_message[-8:])
                        if char == ".":
                            return True  # Stop sniffing

                last_packet_time = current_time

        sniff(timeout=parameter3, stop_filter=process_packet)

        # Convert the binary message to a string
        decoded_message = "".join(
            self.convert_eight_bits_to_character(received_message[i:i + 8])
            for i in range(0, len(received_message), 8)
        )
        self.log_message(decoded_message, log_file_name)
