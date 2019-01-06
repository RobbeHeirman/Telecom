
elementclass RSVPSetTos{ $type, $RSVPElement |

    input
        -> EtherEncap(0x0800, 2:2:2:2:2:2, 3:3:3:3:3:3)
        -> ToDump("check2.pcap")
        -> Strip(14)
        ->classy::RSVPClassifyService($type, $RSVPElement);

    classy[0] //Remember 0 outputs the best effort class
        -> SetIPDSCP(0) // IPDSCP sets the IPTosField: 0 is best effort or routine
        -> output;

    classy[1]
        -> SetIPDSCP(1) //Diffserv classifying is done with underling aggreement, we will use 1 as QOS
        -> output;
}
