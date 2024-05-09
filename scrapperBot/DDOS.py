import csv
import dpkt

def extract_data_from_pcapng(pcapng_file):
    # Define a list to store extracted data
    data = []

    with open(pcapng_file, "rb") as file:
        pcap = dpkt.pcapng.Reader(file)
        
        for _, packet in pcap:
            eth = dpkt.ethernet.Ethernet(packet)
            
            # Only process IP packets
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                
                # Extract relevant fields
                src_ip = dpkt.utils.inet_to_str(ip.src)
                dst_ip = dpkt.utils.inet_to_str(ip.dst)
                src_port = ip.data.sport if hasattr(ip.data, 'sport') else None
                dst_port = ip.data.dport if hasattr(ip.data, 'dport') else None
                protocol = ip.data.__class__.__name__
                duration = ip.len  # Using IP length as duration
                
                # Extract packet-related fields and decode byte strings
                src_add = ":".join("{:02x}".format(x) for x in eth.src)
                des_add = ":".join("{:02x}".format(x) for x in eth.dst)
                pkt_id = ip.id
                from_node = 0  # Assuming the from_node information is not available in the pcapng file
                to_node = 0    # Assuming the to_node information is not available in the pcapng file
                pkt_type = eth.type
                pkt_size = len(packet)
                flags = 0      # Assuming the flags information is not available in the pcapng file
                fid = 0        # Assuming the FID information is not available in the pcapng file
                seq_number = 0 # Assuming the sequence number is not available in the pcapng file
                
                # Additional parameters
                number_of_pkt = 0
                number_of_byte = 0
                node_name_from = ""
                node_name_to = ""
                pkt_in = pkt_out = pkt_r = pkt_delay_node = pkt_rate = byte_rate = pkt_avg_size = utilization = pkt_delay = pkt_send_time = pkt_reseved_time = first_pkt_sent = last_pkt_reseved = 0
                
                # Append extracted data to the list
                data.append([src_add, des_add, pkt_id, from_node, to_node, pkt_type, pkt_size, flags, fid, seq_number,
                             number_of_pkt, number_of_byte, node_name_from, node_name_to, pkt_in, pkt_out, pkt_r, 
                             pkt_delay_node, pkt_rate, byte_rate, pkt_avg_size, utilization, pkt_delay, 
                             pkt_send_time, pkt_reseved_time, first_pkt_sent, last_pkt_reseved])

    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["SRC_ADD", "DES_ADD", "PKT_ID", "FROM_NODE", "TO_NODE", "PKT_TYPE", "PKT_SIZE", "FLAGS", "FID", "SEQ_NUMBER",
                         "NUMBER_OF_PKT", "NUMBER_OF_BYTE", "NODE_NAME_FROM", "NODE_NAME_TO", "PKT_IN", "PKT_OUT", "PKT_R", 
                         "PKT_DELAY_NODE", "PKT_RATE", "BYTE_RATE", "PKT_AVG_SIZE", "UTILIZATION", "PKT_DELAY", 
                         "PKT_SEND_TIME", "PKT_RESEVED_TIME", "FIRST_PKT_SENT", "LAST_PKT_RESEVED"])
        writer.writerows(data)

pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "ddosdata.csv")
