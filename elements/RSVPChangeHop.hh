//
// Created by robbe on 29/12/18.
//

#ifndef TELECOM_RSVPCHANGEHOP_HH
#define TELECOM_RSVPCHANGEHOP_HH

#include "RSVPElement.hh"
#include "RSVPStructs.hh"


CLICK_DECLS

/**
 *
 * @class used to change the HOP object address.
 */
class RSVPChangeHop: public RSVPElement {

public:

    RSVPChangeHop() = default;
    ~RSVPChangeHop() = default;

    const char* class_name() const {return "RSVPChangeHop";}
    const char* port_count() const {return PORTS_1_1;} // Takes a RSVP header places the address of the outgoing interface ip and pushes
    const char* processing() const {return PUSH;}

    int configure(Vector<String>& config, ErrorHandler* errh);

    /**
     * Changes the HOP object in a RSVP message to the IP of the interface that is connected.
     * @param port
     * @param p
     */
    void push(int port, Packet* p);


private:

    RSVPHop* find_hop(Packet* p);



};

CLICK_ENDDECLS
#endif //TELECOM_RSVPCHANGEHOP_HH
