host1::RSVPHost();
host1
	-> IPEncap(46, 2.2.2.2, 1.1.1.1)
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> ToDump(robbe.pcap)
	-> Discard;