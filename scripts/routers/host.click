// Output configuration: 
//
// Packets for the network are put on output 0
// Packets for the host are put on output 1

require(library CompoundElements/RSVPSetTos.click)
require(library CompoundElements/RSVPPacketScheduler.click)

elementclass Host {
	$address, $gateway |

	rsvpHost :: RSVPHost($address);
	rsvpTos :: RSVPSetTos(RSVPHost, rsvpHost);

	// Shared IP input path
	ip :: Strip(14)
		-> CheckIPHeader
		-> rsvpTos
		-> rsvpSched :: RSVPPacketScheduler
		-> rt :: StaticIPLookup(
			$address:ip/32 0,
			$address:ipnet 1,
			0.0.0.0/0 $gateway 1)
		-> [1]output;

	rt[1]
		-> ipgw :: IPGWOptions($address)
		-> FixIPSrc($address)
		-> ttl :: DecIPTTL
		-> frag :: IPFragmenter(1500)
		-> arpq :: ARPQuerier($address)
		-> output;

	ipgw[1]	-> ICMPError($address, parameterproblem)
		-> output;

	ttl[1]	-> ICMPError($address, timeexceeded)
		-> output;

	frag[1]	-> ICMPError($address, unreachable, needfrag)
		-> output;

	// incoming packets
	input	-> HostEtherFilter($address)
		-> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800 23/2E, 12/0800)
		-> arp_res :: ARPResponder($address)
		-> output;

	in_cl[1]
		-> [1]arpq;

	in_cl[2]
		-> Strip(14)
		-> CheckIPHeader
		-> rsvpHost
		-> CheckIPHeader
		-> rt;

	in_cl[3]
		-> ip;

}
