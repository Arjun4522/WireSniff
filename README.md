# WireSniff
'Packet_sniffer_C v2' comes out at 'WireSniff'
# Descrption:
Updated version of `https://github.com/Arjun4522/Packet_sniffer_C`
### Getting Started:
1. Install libpcap for Debian-based distributions using `sudo apt update && sudo apt-get install libpcap-dev`
3. Clone the repository: `https://github.com/Arjun4522/WireSniff`
4. Navigate to the project directory: `cd WireSniff`
5. Compile the program: `gcc -o wiresniff wiresniff.c -lpcap`
6. Run the packet sniffer: `sudo ./wiresniff <interface>`
### Usage:
- Replace `<interface>` with the name of the network interface you want to capture packets from (e.g., eth0, wlan0, etc.).
- The program will start capturing packets and display relevant information for each packet.
### Note:
- Root/superuser privileges are required to capture network packets, hence the `sudo` command in the usage.
