
//src1::RSVPSource();
//src2::RSVPSource();
//
//src1
//	-> Unqueue
//	-> IPEncap(46, 1.35.69.103, 15.15.15.15)
//	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
//	-> ToDump(pull.pcap)
//	-> Discard;
//
//src2
//	-> Queue
//	-> IPEncap(46, 1.35.69.103, 15.15.15.15)
//	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
//	-> ToDump(push.pcap)
//	-> Discard;

ipencap1::IPEncap(46, 2.2.2.2, 1.1.1.1);
host1::RSVPHost(ipencap1);

ipencap2::IPEncap(46, 1.1.1.1, 2.2.2.2);
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

