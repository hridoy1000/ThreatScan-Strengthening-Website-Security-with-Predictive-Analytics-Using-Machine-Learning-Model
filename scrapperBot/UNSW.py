import csv
import dpkt
import time
import random

def extract_data_from_pcapng(pcapng_file):
    data = []

    # Open the PCAPNG file
    with open(pcapng_file, "rb") as file:
        # Create a pcapng reader
        pcap = dpkt.pcapng.Reader(file)
        
        # Previous timestamp for calculating inter-packet arrival time
        prev_timestamp = None
        
        # Initialize variables to hold cumulative values for certain features
        total_spkts = 0
        total_sbytes = 0
        total_dbytes = 0
        
        # Iterate through each packet in the PCAPNG file
        for _, packet in pcap:
            try:
                # Parse the Ethernet frame
                eth = dpkt.ethernet.Ethernet(packet)

                # Extract IP packet
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    
                   
                    timestamp = time.time()  
                    if prev_timestamp is None:
                        dur = 0.0
                    else:
                        dur = timestamp - prev_timestamp
                    
                    spkts = 1  # Number of source packets
                    dpkts = 0  # Number of destination packets
                    sbytes = ip.len  # Source bytes
                    dbytes = 0  # Destination bytes
                    sttl = ip.ttl  # Source TTL
                    dttl = ip.ttl  # Destination TTL
                    sloss = random.randint(0, 10)  # Source packets retransmitted or dropped (random value)
                    dloss = random.randint(0, 10)  # Destination packets retransmitted or dropped (random value)
                    service = ''  # Service
                    sload = random.uniform(100, 1000)  # Source bits per second (random value)
                    dload = random.uniform(100, 1000)  # Destination bits per second (random value)
                    swin = random.randint(100, 1000)  # Source TCP window advertisement value (random value)
                    dwin = random.randint(100, 1000)  # Destination TCP window advertisement value (random value)
                    stcpb = random.randint(1000, 2000)  # Source TCP base sequence number (random value)
                    dtcpb = random.randint(1000, 2000)  # Destination TCP base sequence number (random value)
                    smean_sz = random.randint(50, 500)  # Mean of the flow packet size transmitted by the src (random value)
                    dmean_sz = random.randint(50, 500)  # Mean of the flow packet size transmitted by the dst (random value)
                    trans_depth = random.randint(0, 5)  # Pipelined depth into the connection of HTTP request/response transaction (random value)
                    res_bdy_len = random.randint(100, 10000)  # Actual uncompressed content size of the data transferred from the server's HTTP service (random value)
                    sjit = random.uniform(0, 10)  # Source jitter (mSec) (random value)
                    djit = random.uniform(0, 10)  # Destination jitter (mSec) (random value)
                    stime = int(timestamp)  # Record start time
                    ltime = int(timestamp)  # Record last time
                    sintpkt = random.uniform(0, 10)  # Source interpacket arrival time (mSec) (random value)
                    dintpkt = random.uniform(0, 10)  # Destination interpacket arrival time (mSec) (random value)
                    tcprtt = random.uniform(0, 100)  # TCP connection setup round-trip time, the sum of 'synack' and 'ackdat'. (random value)
                    synack = random.uniform(0, 50)  # TCP connection setup time, the time between the SYN and the SYN_ACK packets. (random value)
                    ackdat = random.uniform(0, 50)  # TCP connection setup time, the time between the SYN_ACK and the ACK packets. (random value)
                    is_sm_ips_ports = random.randint(0, 1)  # If source and destination IP addresses equal and port numbers equal (random value)
                    ct_state_ttl = random.randint(0, 5)  # For each state according to specific range of values for source/destination time to live (random value)
                    ct_flw_http_mthd = random.randint(0, 10)  # No. of flows that has methods such as Get and Post in HTTP service. (random value)
                    is_ftp_login = random.randint(0, 1)  # If the FTP session is accessed by user and password then 1 else 0. (random value)
                    ct_ftp_cmd = random.randint(0, 10)  # No. of flows that has a command in FTP session. (random value)
                    ct_srv_src = random.randint(0, 100)  # No. of connections that contain the same service and source address in 100 connections. (random value)
                    ct_srv_dst = random.randint(0, 100)  # No. of connections that contain the same service and destination address in 100 connections. (random value)
                    ct_dst_ltm = random.randint(0, 100)  # No. of connections of the same destination address in 100 connections according to the last time. (random value)
                    ct_src_ltm = random.randint(0, 100)  # No. of connections of the same source address in 100 connections according to the last time. (random value)
                    ct_src_dport_ltm = random.randint(0, 100)  # No of connections of the same source address and the destination port in 100 connections. (random value)
                    ct_dst_sport_ltm = random.randint(0, 100)  # No of connections of the same destination address and the source port in 100 connections. (random value)
                    ct_dst_src_ltm = random.randint(0, 100)  # No of connections of the same source and the destination address in 100 connections according to the last time. (random value)
                    attack_cat = ''  # The name of each attack category.
                    label = 0  # 0 for normal and 1 for attack records
                    
                    # Update cumulative values
                    total_spkts += spkts
                    total_sbytes += sbytes
                    
                    # Append the calculated features to the data list
                    row = [
                        dur, ip.__class__.__name__, service, '', spkts, dpkts, sbytes, dbytes,
                        0.0, sttl, dttl, sloss, dloss, sload, dload, swin, dwin,
                        stcpb, dtcpb, smean_sz, dmean_sz, trans_depth, res_bdy_len,
                        sjit, djit, stime, ltime, sintpkt, dintpkt, tcprtt, synack,
                        ackdat, is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd,
                        is_ftp_login, ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm,
                        ct_src_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm,
                        attack_cat, label
                    ]
                    data.append(row)
                    
                    prev_timestamp = timestamp
            except Exception as e:
                print("Error processing packet:", e)

    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
            "rate", "sttl", "dttl", "sloss", "dloss", "Sload", "Dload", "swin", "dwin",
            "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
            "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack",
            "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
            "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
            "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
            "attack_cat", "label"
        ])
        writer.writerows(data)

pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "unswdata.csv")

