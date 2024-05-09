import csv
import dpkt

def extract_data_from_pcapng(pcapng_file):
    # Define lists to store extracted data
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
                
                # Extract additional fields
                protocol_type = "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else "UDP"
                service = "HTTP" if dst_port == 80 else "Unknown"  # Example: Identify HTTP service
                
                # Find values for other fields
                src_bytes = len(eth.data.data) if hasattr(eth.data, 'data') else 0
                dst_bytes = len(eth.data.data) if hasattr(eth.data, 'data') else 0
                land = int(ip.src == ip.dst)
                wrong_fragment = 0  
                urgent = 0 
                hot = 0  # Set to 0 since we're not defining hot criteria here
                num_failed_logins = 0  # Set to 0 since we're not defining failed login criteria here
                logged_in = 0  # Set to 0 since we're not defining logged in criteria here
                num_compromised = 0  # Set to 0 since we're not defining compromised criteria here
                root_shell = 0  # Set to 0 since we're not defining root shell criteria here
                su_attempted = 0  # Set to 0 since we're not defining su attempted criteria here
                num_root = 0  # Set to 0 since we're not defining num root criteria here
                num_file_creations = 0  # Set to 0 since we're not defining file creations criteria here
                num_shells = 0  # Set to 0 since we're not defining num shells criteria here
                num_access_files = 0  # Set to 0 since we're not defining access files criteria here
                num_outbound_cmds = 0  # Set to 0 since we're not defining outbound cmds criteria here
                is_host_login = 0  # Set to 0 since we're not defining host login criteria here
                is_guest_login = 0  # Set to 0 since we're not defining guest login criteria here
                count = 0  # Set to 0 since we're not defining count criteria here
                srv_count = 0  # Set to 0 since we're not defining srv count criteria here
                serror_rate = 0.0  # Set to 0.0 since we're not defining serror rate criteria here
                srv_serror_rate = 0.0  # Set to 0.0 since we're not defining srv serror rate criteria here
                rerror_rate = 0.0  # Set to 0.0 since we're not defining rerror rate criteria here
                srv_rerror_rate = 0.0  # Set to 0.0 since we're not defining srv rerror rate criteria here
                same_srv_rate = 0.0  # Set to 0.0 since we're not defining same srv rate criteria here
                diff_srv_rate = 0.0  # Set to 0.0 since we're not defining diff srv rate criteria here
                srv_diff_host_rate = 0.0  # Set to 0.0 since we're not defining srv diff host rate criteria here
                dst_host_count = 0  # Set to 0 since we're not defining dst host count criteria here
                dst_host_srv_count = 0  # Set to 0 since we're not defining dst host srv count criteria here
                dst_host_same_srv_rate = 0.0  # Set to 0.0 since we're not defining dst host same srv rate criteria here
                dst_host_diff_srv_rate = 0.0  # Set to 0.0 since we're not defining dst host diff srv rate criteria here
                dst_host_same_src_port_rate = 0.0  # Set to 0.0 since we're not defining dst host same src port rate criteria here
                dst_host_srv_diff_host_rate = 0.0  # Set to 0.0 since we're not defining dst host srv diff host rate criteria here
                dst_host_serror_rate = 0.0  # Set to 0.0 since we're not defining dst host serror rate criteria here
                dst_host_srv_serror_rate = 0.0  # Set to 0.0 since we're not defining dst host srv serror rate criteria here
                dst_host_rerror_rate = 0.0  # Set to 0.0 since we're not defining dst host rerror rate criteria here
                dst_host_srv_rerror_rate = 0.0  # Set to 0.0 since we're not defining dst host srv rerror rate criteria here
                
                # Append extracted data to the list
                data.append([src_ip, dst_ip, src_port, dst_port, protocol, duration,
                             protocol_type, service, src_bytes, dst_bytes, land,
                             wrong_fragment, urgent, hot, num_failed_logins, logged_in,
                             num_compromised, root_shell, su_attempted, num_root,
                             num_file_creations, num_shells, num_access_files,
                             num_outbound_cmds, is_host_login, is_guest_login, count,
                             srv_count, serror_rate, srv_serror_rate, rerror_rate,
                             srv_rerror_rate, same_srv_rate, diff_srv_rate,
                             srv_diff_host_rate, dst_host_count, dst_host_srv_count,
                             dst_host_same_srv_rate, dst_host_diff_srv_rate,
                             dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
                             dst_host_serror_rate, dst_host_srv_serror_rate,
                             dst_host_rerror_rate, dst_host_srv_rerror_rate])
                # Append other fields to the list as needed

    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "duration",
                         "protocol_type", "service", "src_bytes", "dst_bytes", "land",
                         "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
                         "num_compromised", "root_shell", "su_attempted", "num_root",
                         "num_file_creations", "num_shells", "num_access_files",
                         "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
                         "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
                         "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
                         "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                         "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
                         "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
                         "dst_host_serror_rate", "dst_host_srv_serror_rate",
                         "dst_host_rerror_rate", "dst_host_srv_rerror_rate"])
        writer.writerows(data)

pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "KDDCUPdata.csv")
