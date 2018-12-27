/**
 * @authors: Robbe Heirman, Jules Desmet
 * @brief: Class representing a click node element that will handle path messages.
**/

#ifndef TELECOM_RSVPNODE_H
#define TELECOM_RSVPNODE_H

#include <click/element.hh>


CLICK_DECLS

class RSVPNode: public Element {

public:
    /// Constructor destructor
    RSVPNode() = default;
    ~RSVPNode() = default;

    const char* class_name() const {return "RSVPNode";}
    const char* port_count() const {return "1/1";} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

    //void push(int port, Packet* p);


};

CLICK_ENDDECLS

#endif //TELECOM_RSVPNODEPATH_H
