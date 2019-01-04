
host1::RSVPHost();
host2::RSVPHost();

host1
	-> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
	-> t1 :: Tee 
	-> Strip(14)
	-> MarkIPHeader
	-> host2;

host2
	-> EtherEncap(0x0800, 3:3:3:3:3:3, 2:2:2:2:2:2)
	-> t2 :: Tee
	-> Strip(14)
	-> MarkIPHeader
	-> host1;

dump :: ToDump(test.pcap);

t1[1]	-> dump;
t2[1]	-> dump;

