
elementclass RSVPSetTos{ $type, $RSVPElement |

    input
        ->classy::RSVPClassifyService($type, $RSVPElement);

    classy[0] //Remember 0 outputs the best effort class
        -> SetIPDSCP(0) // IPDSCP sets the IPTosField: 0 is best effort or routine
        -> output;

    classy[1]
        -> SetIPDSCP(1) //Diffserv classifying is done with underling aggreement, we will use 1 as QOS
        -> output;
}
