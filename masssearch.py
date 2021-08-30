import gc
import requests
import ipaddress
import sys
from bounded_pool_executor import BoundedProcessPoolExecutor
import urllib3
urllib3.disable_warnings()

header = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36'}

if len(sys.argv) < 3:
        print("Missing argument...")
        exit()

def initialize_threads():
        futures = []
        with BoundedProcessPoolExecutor(max_workers=int(sys.argv[2])) as executor:
                for ip in ipaddress.IPv4Network((sys.argv[1])):
                        executor.submit(scan_ip, ip)

def scan_ip(ip):
        host = "http://" + str(ip) + "/vulnerable_folder/"
        print("Trying to fetch: " + host)
        try:
                r = requests.get(host, headers=header, verify=False, timeout=5)
                body = r.text
                if 'vulnerable page text' in body.lower():
                        print('Vulnerability FOUND: ' + host)
                        with open("output.txt", "a") as txt_file:
                                txt_file.write(host + "\n")
        except:
                pass

print("Starting scan on " + str(sys.argv[1]) + " with " + str(sys.argv[2]) + " threads")
initialize_threads()