
ipencap1::IPEncap(46, 8.7.6.5, 4.3.2.1);
host1::RSVPHost(ipencap1);

ipencap2::IPEncap(46, 1.2.3.4, 5.6.7.8);
host2::RSVPHost(ipencap2);

host1
	-> ipencap1
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> ToDump(test1.pcap)
	-> Strip(14)
	-> StripIPHeader
	-> host2;

host2
	-> ipencap2
	-> EtherEncap(0x0800, 3:3:3:3:3:3, 2:2:2:2:2:2)
	-> ToDump(test2.pcap)
	-> Discard;

