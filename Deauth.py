import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading

#searches for networks and lists them

def add(packet, network):
	#checks for hidden networks
	essid = packet[Dot11Elt].info if '\x00' not in packet [Dot11Elt].info and packet [Dot11Elt].info != '' else 'Hidden SSID'
	bssid = packet[Dot11].addr3
	channel = int(ord(packet[Dot11Elt:3].info))
	if bssid not in network:
			network[bssid] = (essid, channel)
			print "{0:5}\t{1:30}\t{2:20}".format(channel, essid, bssid)
			
def switch_channel(interface):
	#switches between WiFi channels
	while True:
		try:
			#11 channels standard in US, 13 in other countries
			channel = random.randrange(1,13)
			os.system("iwconfig %s channel %d" %(interface, channel))
			time.sleep(1)
		except KeyboardInterrupt:
			break
			
def stop_search(signal, frame):
	global stop_sniff
	stop_sniff = True
	channel_hop.terminate()
	channel_hop.join()
	
def cont_sniff(packet):
	return stop_sniff
	
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = 'aircrack.py') #uses aircrack-ng
	args = parser.parse_args()
	networks = {}
	print('CTRL+c to cancel')
	stop_sniff = False
	print '='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel', 'ESSID', 'BSSID') + '='*100
	channel_hop = Process(target = switch_channel, args=(args.interface,))
	channel_hop.start()
	signal.signal(signal.SIGINT, stop_search)
	sniff(lfilter = lambda x: (x,haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=cont_sniff, prn=lambda x: add(x, networks))