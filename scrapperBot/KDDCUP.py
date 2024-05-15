import csv
import dpkt
import random

def extract_data_from_pcapng(pcapng_file):
    data = []

    with open(pcapng_file, "rb") as file:
        pcap = dpkt.pcapng.Reader(file)
        
        for _, packet in pcap:
            eth = dpkt.ethernet.Ethernet(packet)
            
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                
                src_ip = dpkt.utils.inet_to_str(ip.src)
                dst_ip = dpkt.utils.inet_to_str(ip.dst)
                src_port = ip.data.sport if hasattr(ip.data, 'sport') else None
                dst_port = ip.data.dport if hasattr(ip.data, 'dport') else None
                protocol = ip.data.__class__.__name__
                duration = ip.len
                
                protocol_type = "TCP" if isinstance(ip.data, dpkt.tcp.TCP) else "UDP"
                service = "HTTP" if dst_port == 80 else "Unknown"
                
                src_bytes = len(eth.data.data) if hasattr(eth.data, 'data') else 0
                dst_bytes = len(eth.data.data) if hasattr(eth.data, 'data') else 0
                land = int(ip.src == ip.dst)
                wrong_fragment = 0  
                urgent = 0 
                hot = random.randint(1, 10)  
                num_failed_logins = random.randint(0, 5)  
                logged_in = random.randint(0, 1)  
                num_compromised = 0  
                root_shell = 0  
                su_attempted = 0  
                num_root = 0  
                num_file_creations = 0  
                num_shells = 0  
                num_access_files = 0  
                num_outbound_cmds = 0  
                is_host_login = 0  
                is_guest_login = 0  
                count = 9  
                srv_count = 0  
                serror_rate = 1.0  
                srv_serror_rate = 0.0  
                rerror_rate = 0.0  
                srv_rerror_rate = 0.0  
                same_srv_rate = 0.0  
                diff_srv_rate = 0.0  
                srv_diff_host_rate = 0.0  
                dst_host_count = 0  
                dst_host_srv_count = 0  
                dst_host_same_srv_rate = 0.0  
                dst_host_diff_srv_rate = 0.0  
                dst_host_same_src_port_rate = 0.0  
                dst_host_srv_diff_host_rate = 0.03	 
                dst_host_serror_rate = 0.0  
                dst_host_srv_serror_rate = 0.0  
                dst_host_rerror_rate = 0.0  
                dst_host_srv_rerror_rate = 0.0  
                flag='SF'
                
                data.append([duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
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

    return data

def save_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["duration","protocol_type", "service","flag", "src_bytes", "dst_bytes", "land",
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
                         "dst_host_rerror_rate", "dst_host_srv_rerror_rate","outcome"])
        writer.writerows(data)

pcapng_file = "p12.pcapng"
data = extract_data_from_pcapng(pcapng_file)
save_to_csv(data, "KDDCUPdata.csv")
