
src1::RSVPSource();
src2::RSVPSource();

src1
	-> Unqueue
	-> IPEncap(46, 1.35.69.103, 15.15.15.15)
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> ToDump(pull.pcap)
	-> Discard;

src2
	-> Queue
	-> IPEncap(46, 1.35.69.103, 15.15.15.15)
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> ToDump(push.pcap)
	-> Discard;
