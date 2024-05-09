import socket
from urllib.parse import urlparse

def url_to_ip(url):
    try:
        # Parse the URL to extract the hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Resolve the IP address of the hostname
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        # Handle the case where the URL cannot be resolved to an IP address
        return None

# Example usage:
url = "https://www.nasa.gov"
ip_address = url_to_ip(url)
if ip_address:
    print(f"The IP address of {url} is: {ip_address}")
else:
    print(f"Failed to resolve the IP address of {url}")
