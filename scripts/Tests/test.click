
require(library ../CompoundElements/RSVPSetTos.click)

host1 :: RSVPHost(192.168.10.1);
host2 :: RSVPHost(192.168.11.1);
dump :: ToDump(test.pcap);

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

RatedSource(RATE 1, LENGTH 46)
	-> UDPIPEncap(192.168.10.1, 7, 192.168.11.1, 2222)
	-> RSVPSetTos(RSVPHost, host1)
	-> EtherEncap(0x0800, 1:1:1:1:1:1, 1:1:1:1:1:1)
	-> dump;

t1[1]	-> dump;
t2[1]	-> dump;

dump	-> Discard;


