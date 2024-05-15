import csv
import dpkt
import random
import time

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
                from_node = 1  # Assuming from_node is 1
                to_node = 2    # Assuming to_node is 2
                pkt_type = eth.type
                pkt_size = len(packet)
                seq_number = ip.data.seq if hasattr(ip.data, 'seq') else None # Assuming SEQ_NUMBER is the sequence number from IP header
                number_of_pkt = 1 # Assuming only one packet
                number_of_byte = pkt_size
                pkt_in = pkt_out = pkt_r = pkt_delay_node = pkt_rate = byte_rate = pkt_avg_size = utilization = pkt_delay = pkt_send_time = pkt_reseved_time = first_pkt_sent = last_pkt_reseved = 0

               
                flags = ip.off & dpkt.ip.IP_DF  
                flags_0 = int(flags != 0)  
                flags = ip.off & dpkt.ip.IP_MF  
                flags_1 = int(flags != 0) 

                pkt_in = random.randint(800, 1200)
                pkt_out = random.randint(700, 1000)  
                pkt_r = random.randint(20, 50) 
                pkt_delay_node = random.uniform(1.0, 5.0)  
                pkt_rate = random.randint(400, 600)  
                byte_rate = random.randint(4000, 6000)
                pkt_avg_size = random.randint(800, 1200)  
                utilization = random.randint(70, 90) 
                pkt_delay = random.uniform(5.0, 15.0)  


                current_time = int(time.time())
                pkt_send_time = random.randint(current_time - 3600, current_time) 
                pkt_reseved_time = pkt_send_time + random.randint(1, 60) 
                first_pkt_sent = pkt_send_time  
                last_pkt_reseved = pkt_reseved_time 


                
                # Append extracted data to the list
                data.append([pkt_size, seq_number, number_of_pkt, number_of_byte, pkt_in, pkt_delay_node, pkt_rate,
             byte_rate, pkt_delay, first_pkt_sent, last_pkt_reseved, flags_0, flags_1])


    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["PKT_SIZE","SEQ_NUMBER","NUMBER_OF_PKT", "NUMBER_OF_BYTE", "PKT_IN", "PKT_DELAY_NODE", "PKT_RATE",
                         "BYTE_RATE", "PKT_DELAY","FIRST_PKT_SENT", "LAST_PKT_RESEVED", "FLAGS_0", "FLAGS_1"])
        writer.writerows(data)

pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "ddosdata.csv")
