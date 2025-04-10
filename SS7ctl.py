import argparse
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.contrib import s7

# Initialize logging
logging.basicConfig(level=logging.INFO)

def extract_sms(pcap_file):
    """
    Extract and decode SMS messages from SS7 MAP packets in the pcap file.
    """
    packets = rdpcap(pcap_file)
    sms_messages = []
    for pkt in packets:
        if pkt.haslayer(s7.SS7MAP):
            if pkt[s7.SS7MAP].cmd == 0x05:  # MAP: SendRoutingInfo (used for SMS)
                try:
                    sms_message = pkt[s7.SS7MAP].data.decode('utf-8')
                    sms_messages.append(sms_message)
                    logging.info(f"SMS Message: {sms_message}")
                except Exception as e:
                    logging.error(f"Failed to decode SMS: {str(e)}")
    return sms_messages

def location_tracking(pcap_file):
    """
    Extract and decode location updates from SS7 MAP packets.
    """
    packets = rdpcap(pcap_file)
    locations = []
    for pkt in packets:
        if pkt.haslayer(s7.SS7MAP):
            if pkt[s7.SS7MAP].cmd == 0x06:  # MAP: LocationUpdate
                location = {
                    "IMEI": pkt[s7.SS7MAP].IMEI,
                    "MSISDN": pkt[s7.SS7MAP].MSISDN,
                    "Timestamp": pkt.time
                }
                locations.append(location)
                logging.info(f"Location Update: {location}")
    return locations

def analyze_ss7(pcap_file):
    """
    General SS7 packet analysis, showing SS7 MAP and CAP packets.
    """
    packets = rdpcap(pcap_file)
    ss7_map_count = 0
    ss7_cap_count = 0
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 2905:  # SS7 MAP
                ss7_map_count += 1
                logging.info(f"SS7 MAP Packet: {pkt.summary()}")
            elif pkt[TCP].dport == 2906:  # SS7 CAP
                ss7_cap_count += 1
                logging.info(f"SS7 CAP Packet: {pkt.summary()}")
    
    logging.info(f"Total SS7 MAP packets: {ss7_map_count}")
    logging.info(f"Total SS7 CAP packets: {ss7_cap_count}")

def main():
    parser = argparse.ArgumentParser(description="SS7 Signaling Analysis Tool")
    parser.add_argument("-i", "--input", required=True, help="Input pcap file")
    parser.add_argument("-s", "--sms", action="store_true", help="Extract SMS messages")
    parser.add_argument("-l", "--location", action="store_true", help="Track location updates")
    args = parser.parse_args()

    logging.info(f"Loading PCAP file: {args.input}")
    
    if args.sms:
        logging.info("Extracting SMS messages from SS7 MAP packets...")
        sms_messages = extract_sms(args.input)
        if sms_messages:
            logging.info(f"Extracted {len(sms_messages)} SMS messages.")
        else:
            logging.info("No SMS messages found.")
    
    if args.location:
        logging.info("Tracking location updates from SS7 MAP packets...")
        locations = location_tracking(args.input)
        if locations:
            logging.info(f"Tracked {len(locations)} location updates.")
        else:
            logging.info("No location updates found.")

    logging.info("Performing SS7 analysis...")
    analyze_ss7(args.input)

if __name__ == "__main__":
    main()
