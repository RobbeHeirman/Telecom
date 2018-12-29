/**
 * @authors: Robbe Heirman, Jules Desmet
 * @brief: Class representing a click node element that will handle path messages.
**/

#ifndef TELECOM_RSVPNODE_H
#define TELECOM_RSVPNODE_H


#include <click/hashtable.hh>
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
    const char* port_count() const {return PORTS_1_1;} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

    int configure(Vector<String>& config, ErrorHandler* errh);

    /**
     *
     * @param port Package will come in. This is the CLICK ELEMENT port. This element has 0 in and outgoing port so 0
     * @param p the packet comming in
     * @brief: Handles a incomming RSVP message at the node. CURRENTLY: Path
     */
    void push(int port, Packet* p);


private:

    /**
     * Wille handle accordingly if a message is a path message.
     * @param p
     */
    void handle_path_message(Packet* p);

    /**
     * Functions that converts a session & sender object package to a uint64 So we can use this as a key for session
     * bookkeeping.
     */
    uint64_t session_to_key(RSVPSession* session);
    uint64_t sender_template_to_key(RSVPSenderTemplate* sender_template);

    // needs to place his ip address in next hop.
    IPAddress m_address_info;

    /**
     * PathState is a struct for bookkeeping of the RSVP path sof state.
     * @member: prev_hop, notes the IP Unicast address of the prev hop, will be found in hop object of rsvp message.
     */
    struct PathState{

        IPAddress prev_hop; // prev_hop node
        vector<RSVPPolicyData> policy_data; // Potential policy data
        RSVPSenderTSpec t_spec; // TSpec element

    };

    typedef HashTable<uint64_t, HashTable<uint64_t, PathState>> PathStateMap;
    PathStateMap m_path_state;

};

CLICK_ENDDECLS

#endif //TELECOM_RSVPNODEPATH_H
