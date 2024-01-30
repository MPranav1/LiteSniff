# LiteSniff
This Python script is designed to capture and analyze raw IP packets using a raw socket. It extracts various details from the IP header, such as version, header length, type of service, length, identification, flags, fragment offset, time to live, protocol, checksum, source address, and destination address.

### Prerequisites
Before running the script, ensure you have the following:

* Python installed on your system.
* Admin or root privileges may be required to run the script (especially on Windows).

### Usage
1. Clone the repository:
   
   git clone [LiteSniff](https://github.com/MPranav1/LiteSniff.git)

   cd LiteSniff
   
3. Run the script:

   python sniffer.py
   Make sure to use Python 3.

### Important Note
* This script uses raw sockets and may require elevated privileges.
* The script is currently configured to capture all IP packets on the network interface.
* Ensure that you have the necessary permissions to run raw socket operations.

  
