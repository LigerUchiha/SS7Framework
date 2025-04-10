# SS7Framework

Simulated SS7 interception and signaling research toolkit.

## Features
- **SMS Interception**: Extract and decode SMS messages from SS7 MAP packets.
- **Location Tracking**: Track MSISDN (Mobile Subscriber ISDN) and IMEI information for location updates.
- **Packet Decoding**: Decode SS7 MAP and CAP packets, useful for mobile network security research.
- **Logging and Debugging**: Integrated logging system for tracking the analysis process and errors.

## Installation
Ensure you have `scapy` installed:

```bash
pip install scapy
Usage
Extract SMS Messages from a PCAP File:
bash
Copy code
python ss7ctl.py -i sample.pcap -s
Track Location Updates:
bash
Copy code
python ss7ctl.py -i sample.pcap -l
Full Analysis (MAP and CAP):
bash
Copy code
python ss7ctl.py -i sample.pcap
Example Output:
csharp
Copy code
Extracting SMS messages from SS7 MAP packets...
SMS Message: "Hello, this is a test SMS"
Tracking location updates from SS7 MAP packets...
Location Update: {'IMEI': '123456789012345', 'MSISDN': '9876543210', 'Timestamp': 1609459200}
Performing SS7 analysis...
Total SS7 MAP packets: 10
Total SS7 CAP packets: 5
