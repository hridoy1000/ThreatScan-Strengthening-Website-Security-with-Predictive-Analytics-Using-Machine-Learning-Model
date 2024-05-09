import csv
import dpkt

def extract_data_from_pcapng(pcapng_file):
    src_ips = []
    dst_ips = []
    src_ports = []
    dst_ports = []
    protocols = []
    durations = []
    sbytes = []
    dbytes = []
    sttl = []
    dttl = []
    sloss = []
    dloss = []
    service = []
    sload = []
    dload = []
    spkts = []
    dpkts = []
    swin = []
    dwin = []
    stcpb = []
    dtcpb = []
    smeansz = []
    dmeansz = []
    trans_depth = []
    res_bdy_len = []
    sjit = []
    djit = []
    stime = []
    ltime = []
    sintpkt = []
    dintpkt = []
    tcprtt = []
    synack = []
    ackdat = []
    is_sm_ips_ports = []
    ct_state_ttl = []
    ct_flw_http_mthd = []
    is_ftp_login = []
    ct_ftp_cmd = []
    ct_srv_src = []
    ct_srv_dst = []
    ct_dst_ltm = []
    ct_src_ltm = []
    ct_src_dport_ltm = []
    ct_dst_sport_ltm = []
    ct_dst_src_ltm = []
    attack_cat = []

    # Open the PCAPNG file
    with open(pcapng_file, "rb") as file:
        # Create a pcapng reader
        pcap = dpkt.pcapng.Reader(file)
        
        # Iterate through each packet in the PCAPNG file
        for _, packet in pcap:
            # Parse the Ethernet frame
            eth = dpkt.ethernet.Ethernet(packet)

            # Extract IP packet
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data

                # Extract source and destination IP addresses
                src_ips.append(dpkt.utils.inet_to_str(ip.src))
                dst_ips.append(dpkt.utils.inet_to_str(ip.dst))

                # Extract source and destination port numbers (if available)
                src_ports.append(ip.data.sport if hasattr(ip.data, 'sport') else None)
                dst_ports.append(ip.data.dport if hasattr(ip.data, 'dport') else None)

                # Extract protocol
                protocols.append(ip.data.__class__.__name__)

                # Extract duration (you may need to adjust this based on your specific dataset)
                durations.append(ip.len)

                # Extract additional parameters
                sbytes.append(ip.len)  # Example: Using IP length as source bytes
                dbytes.append(0)  # Example: Set destination bytes to 0 for simplicity
                sttl.append(0)  # Example: Set source time to live to 0
                dttl.append(0)  # Example: Set destination time to live to 0
                sloss.append(0)  # Example: Set source loss to 0
                dloss.append(0)  # Example: Set destination loss to 0
                service.append('')  # Example: Set service to empty string
                sload.append(0.0)  # Example: Set source load to 0.0
                dload.append(0.0)  # Example: Set destination load to 0.0
                spkts.append(0)  # Example: Set source packets to 0
                dpkts.append(0)  # Example: Set destination packets to 0
                swin.append(0)  # Example: Set source TCP window to 0
                dwin.append(0)  # Example: Set destination TCP window to 0
                stcpb.append(0)  # Example: Set source TCP base sequence number to 0
                dtcpb.append(0)  # Example: Set destination TCP base sequence number to 0
                smeansz.append(0)  # Example: Set source mean size to 0
                dmeansz.append(0)  # Example: Set destination mean size to 0
                trans_depth.append(0)  # Example: Set transaction depth to 0
                res_bdy_len.append(0)  # Example: Set response body length to 0
                sjit.append(0.0)  # Example: Set source jitter to 0.0
                djit.append(0.0)  # Example: Set destination jitter to 0.0
                stime.append(0)  # Example: Set start time to 0
                ltime.append(0)  # Example: Set last time to 0
                sintpkt.append(0.0)  # Example: Set source interpacket arrival time to 0.0
                dintpkt.append(0.0)  # Example: Set destination interpacket arrival time to 0.0
                tcprtt.append(0.0)  # Example: Set TCP connection setup round-trip time to 0.0
                synack.append(0.0)  # Example: Set SYN-ACK time to 0.0
                ackdat.append(0.0)  # Example: Set ACK-DAT time to 0.0
                is_sm_ips_ports.append(0)  # Example: Set is_sm_ips_ports to 0
                ct_state_ttl.append(0)  # Example: Set connection state TTL to 0
                ct_flw_http_mthd.append(0)  # Example: Set flow HTTP method count to 0
                is_ftp_login.append(0)  # Example: Set is_ftp_login to 0
                ct_ftp_cmd.append(0)  # Example: Set FTP command count to 0
                ct_srv_src.append(0)  # Example: Set connection count to same service from source address to 0
                ct_srv_dst.append(0)  # Example: Set connection count to same service from destination address to 0
                ct_dst_ltm.append(0)  # Example: Set connection count to same destination address to 0
                ct_src_ltm.append(0)  # Example: Set connection count to same source address to 0
                ct_src_dport_ltm.append(0)  # Example: Set connection count to same source address and destination port to 0
                ct_dst_sport_ltm.append(0)  # Example: Set connection count to same destination address and source port to 0
                ct_dst_src_ltm.append(0)  # Example: Set connection count to same destination and source address to 0
                attack_cat.append('')  # Example: Set attack category to empty string

    # Return extracted data
    return (
        src_ips, dst_ips, src_ports, dst_ports, protocols, durations,
        sbytes, dbytes, sttl, dttl, sloss, dloss, service, sload, dload,
        spkts, dpkts, swin, dwin, stcpb, dtcpb, smeansz, dmeansz,
        trans_depth, res_bdy_len, sjit, djit, stime, ltime,
        sintpkt, dintpkt, tcprtt, synack, ackdat,
        is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd, is_ftp_login,
        ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm,
        ct_src_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm,
        attack_cat
    )

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "src_ips", "dst_ips", "src_ports", "dst_ports", "protocols", "durations",
            "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
            "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz",
            "trans_depth", "res_bdy_len", "sjit", "djit", "stime", "ltime",
            "sintpkt", "dintpkt", "tcprtt", "synack", "ackdat",
            "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login",
            "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
            "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
            "attack_cat"
        ])
        writer.writerows(zip(*data))

# Example usage
pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "unswdata.csv")
