/**
 * @authors: Robbe Heirman, Jules Desmet
 * @brief: Class representing a click node element that will handle path messages.
**/

#ifndef TELECOM_RSVPNODE_H
#define TELECOM_RSVPNODE_H


#include "RSVPElement.hh"


CLICK_DECLS
/**
 * @class
 * @brief: Represents a Node capable of handling RSVP messages. Will handle according the received message
 * see rsvp messages.
 */

class RSVPNode: public RSVPElement {


public:
    /// Constructor destructor
    RSVPNode();
    ~RSVPNode() = default;

    /// Standard click functions
    const char* class_name() const {return "RSVPNode";}
    const char* port_count() const {return "-/-";}// Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

    int configure(Vector<String>& config, ErrorHandler* errh);

    /**
     *
     * @param port Package will come in. This is the CLICK ELEMENT port. This element has 0 in and outgoing port so 0
     * @param p the packet comming in
     * @brief: Handles a incomming RSVP message at the node. CURRENTLY: Path
     */
    void push(int port, Packet* p);
    Vector<IPAddress> m_interfaces;

private:
    /**
     * Wille handle accordingly if a message is a path message.
     * @param p
     */
    void handle_path_message(Packet* p, int port);
    void handle_resv_message(Packet* p, int port);
    bool handle_path_tear_message(Packet* p, int port);
};

CLICK_ENDDECLS

#endif //TELECOM_RSVPNODEPATH_H
