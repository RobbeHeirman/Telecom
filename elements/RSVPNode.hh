/**
 * @authors: Robbe Heirman, Jules Desmet
 * @brief: Class representing a click node element that will handle path messages.
**/

#ifndef TELECOM_RSVPNODE_H
#define TELECOM_RSVPNODE_H

#include <click/element.hh>
#include <click/glue.hh>
#include <click/standard/addressinfo.hh>
#include <click/hashmap.hh>
#include "RSVPStructs.hh"

CLICK_DECLS

class RSVPNode: public Element {

public:
    /// Constructor destructor
    RSVPNode()  = default ;
    ~RSVPNode() = default;

    /// Standard click functions
    const char* class_name() const {return "RSVPNode";}
    const char* port_count() const {return PORTS_1_1;} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

    int configure(Vector<String>& config, ErrorHandler* errh);
    void push(int port, Packet* p);


private:
    // needs to place his ip address in next hop.
    IPAddress m_address_info;

    // "These Path messages
    // store "path state" in each node along the way. This path state
    // includes at least the unicast IP address of the previous hop node,
    // which is used to route the Resv messages hop-by-hop in the reverse
    // direction."
    //
    // Bookkeeping for pathstate <Session ID, IP>
    HashMap<int, IPAddress> m_path_state;


};

CLICK_ENDDECLS

#endif //TELECOM_RSVPNODEPATH_H
