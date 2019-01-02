
host1::RSVPHost();
host2::RSVPHost();

host1
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> ToDump(test1.pcap)
	-> Strip(14)
	-> MarkIPHeader
	-> host2;

host2
	-> EtherEncap(0x0800, 3:3:3:3:3:3, 2:2:2:2:2:2)
	-> ToDump(test2.pcap)
	-> Strip(14)
	-> MarkIPHeader
	-> host1;

