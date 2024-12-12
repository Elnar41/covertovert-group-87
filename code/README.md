# Covert Timing Channel Exploiting Packet Inter-Arrival Times Using DNS

This project demonstrates a covert timing channel—a method of secret communication that utilizes timing information to encode and transmit data. Specifically, it exploits **packet inter-arrival times** in DNS queries to convey binary messages between a sender and a receiver. The project showcases the potential risks of such techniques in network security and provides a practical implementation to study and understand covert channels.

## Overview

Covert channels allow data transmission through non-traditional means, bypassing standard communication protocols. In this project:
- **Sender** encodes a binary message into the timing of DNS packets.
- **Receiver** decodes the binary message based on the timing of received DNS packets.

### Key Features
- Utilizes DNS protocol, a commonly used and essential network service, making detection of the covert channel more challenging.
- Implements timing-based encoding and decoding of binary messages.
- Considers network delay and variability to ensure reliability in communication.

---

## How It Works

### Sender
1. **Binary Message Creation**: The sender generates a binary message to transmit.
2. **Packet Transmission**:
   - A **short delay** (e.g., 0.001-0.01 seconds) encodes a binary `0`.
   - A **long delay** (e.g., 1.1-3 seconds) encodes a binary `1`.
3. **Packet Sending**: The sender uses DNS query packets to carry the encoded timing information.
4. **Network Consideration**: Parameters are chosen to account for potential network delays, ensuring message integrity.

### Receiver
1. **Packet Sniffing**: The receiver monitors DNS packets using a specific filter (e.g., UDP port 53).
2. **Timing Analysis**:
   - Measures the inter-arrival times of received packets.
   - Interprets short inter-arrival times as `0` and long inter-arrival times as `1`.
3. **Message Decoding**:
   - Groups bits into bytes (8 bits each) and converts them into readable characters.
   - Stops decoding upon receiving a predefined end marker (e.g., `.`).
4. **Logging**: Logs the decoded message for further analysis or reference.

---

## Project Files

### 1. `covert_channel.py`
The main implementation file containing:
- The `send()` method for encoding and transmitting messages.
- The `receive()` method for decoding and reconstructing messages.

### 2. `CovertChannelBase.py`
Includes helper functions, such as:
- Logging and message conversion.
- Random binary message generation for testing.

### 3. `README.md`
This document, explaining the project in detail.

---

## How to Run the Project

### Prerequisites
- **Python 3.10.12**: Ensure Python is installed on your system.
- **Scapy**: A powerful Python library for packet manipulation and network analysis.

Install dependencies using:
```bash
pip install scapy
```

### Docker Setup

This project uses a containerized environment with Docker. Follow the steps below:

1. **Install Docker**:
   - Ensure Docker and optionally the Compose V2 plugin are installed.
   - Install VSCode for development.
   - Configure Docker to run as a non-root user.

2. **Start Docker Containers**:
   To start the sender and receiver containers:
   ```bash
   docker compose up -d
   ```

3. **Stop Docker Containers**:
   To stop the sender and receiver containers:
   ```bash
   docker compose down
   ```

4. **Attach to Containers**:
   - Attach to the sender container:
     ```bash
     docker exec -it sender bash
     ```
   - Attach to the receiver container:
     ```bash
     docker exec -it receiver bash
     ```

   Once inside the containers, use `ip addr` or `ifconfig` to view the network configuration (work on `eth0`).

---

## How to Test

1. **Receiver**:
   - Start the receiver container. All parameters are read from the `config.json` file. No manual setup is required.

2. **Sender**:
   - Start the sender container. All parameters are also read from the `config.json` file.

3. **Compare Results**:
   - Run the `make compare` command inside one of the containers. This will read from the `Makefile` and display the results.
   - Check the log files for additional verification.

---

## Applications and Risks

### Applications
- Educational: Demonstrates covert communication methods.
- Research: Explores timing channels in networking.

### Risks
This project highlights security vulnerabilities in network protocols. Covert channels can:
- Be used for unauthorized data exfiltration.
- Bypass firewalls and monitoring systems.

### Ethical Use
This project is intended **only for educational purposes**. Unauthorized use of covert channels is illegal and unethical. Ensure you have permission before deploying this system.

---

## Key Considerations

1. **Network Latency**: Adjust parameters to account for variability in network delays.
2. **Message Integrity**: Use an end marker (e.g., `.`) to ensure the message is decoded correctly.
3. **Detection**: Covert channels can be detected through advanced monitoring tools; this project demonstrates the challenge of maintaining secrecy.

---

## Conclusion

This project serves as a practical example of covert timing channels using DNS, providing insights into their implementation, risks, and ethical considerations. It aims to enhance understanding of network vulnerabilities and foster discussions on secure communication practices.

