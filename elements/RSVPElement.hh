//
// Created by robbe on 29/12/18.
//

#ifndef TELECOM_RSVPELEMENT_H
#define TELECOM_RSVPELEMENT_H

#include "../ip/ipencap.hh"
#include <clicknet/ether.h>
#include <click/element.hh>
#include <click/vector.hh>
#include "RSVPStructs.hh"
#include <click/error.hh>


CLICK_DECLS


/**
 * Struct to store a sender template; similar to RSVPSenderTemplate but without the headers
 */
struct FlowID
{
    in_addr source_address;
    uint16_t source_port;

    /**
     * Helper function to turn a FlowID object into a valid key for maps, tables...
     */
    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }
};


/**
 * Struct to store a session; similar to RSVPSession but without the header
 */
struct SessionID
{
    in_addr destination_address;
    uint16_t destination_port;
    uint8_t proto;

    /**
     * Helper function to turn a SessionID object into a valid key for maps, tables...
     */
    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }
};


/**
 * Struct to store a (FF) flow descriptor consisting of a RSVPFlowSpec and RSVPFilterSpec object
 */
struct FlowDescriptor
{
    RSVPFlowSpec* flow_spec;
    RSVPFilterSpec* filter_spec;
};


/**
 * @class
 * Abstract class for RSVPElements
 */
class RSVPElement: public Element
{
public:

    const char* class_name() const {return "RSVPElement";}
    const char* port_count() const {return PORTS_1_1;} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

protected:
    /**
     * Helper function that will help us find package ptrs.
     * @param: Packet is a ptr to package where we want to extract the path ptrs.
     */
    void find_path_ptrs(Packet*& p, RSVPSession*& session, RSVPHop*& hop, RSVPSenderTemplate*& sender,
                        RSVPSenderTSpec*& tspec, Vector<RSVPPolicyData*>& policy_data);

    /**
     * Helper function that will help us find package pointers in RESV_TEAR messages
     * @param packet a pointer to the packet containing the RESV_TEAR message
     * @return whether all pointers were successfully found
     */
    bool find_resv_tear_ptrs(const Packet *const packet,
                             RSVPSession*& session,
                             RSVPHop*& hop,
                             RSVPStyle*& style,
                             Vector<RSVPFilterSpec*>& filter_specs);

    /**
     * Helper function that will help us find package pointers in RESV_CONF messages
     * @param packet a pointer to the packet containing the RESV_CONF message
     * @return whether all pointers were successfully found
     */
    bool find_resv_conf_ptrs(const Packet *const packet,
                             RSVPSession*& session,
                             RSVPErrorSpec*& error_spec,
                             RSVPResvConfirm*& resv_confirm,
                             RSVPStyle*& style,
                             Vector<FlowDescriptor>& flow_descriptor_list);

    /**
     * Helper function that creates a new PATH_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_err(const SessionID& session_id, const FlowID& sender_id);

    /**
     * Helper function that creates a new RESV_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_err(const SessionID& session_id, const FlowID& sender_id);

    /**
     * Helper function that creates a new PATH_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_tear(const SessionID& session_id, const FlowID& sender_id);

    /**
     * Helper function that creates a new RESV_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_tear(const SessionID& session_id, const FlowID& sender_id);

    /**
     * Function that sets the source and destination address in the IPEncap element
     */
    void set_ipencap(const in_addr& source, const in_addr& destination);

    /**
     * Function that sends an error to the default handler if the condition is true
     */
    static inline bool check(bool condition, const String& message) {

        if (condition) {
            ErrorHandler::default_handler()->error(message.c_str());
        }
        return condition;
    }


    // needs to place his ip address in next hop.
    IPAddress m_address_info;

    // The IPEncap element that (should) encapsulate(s) any packet sent out by the RSVPHost element
    IPEncap* m_ipencap;

    // The headroom needed for an ether and ip header
    static constexpr unsigned int s_headroom {sizeof(click_ip) + 4 + sizeof(click_ether)};
};

CLICK_ENDDECLS

#endif //TELECOM_RSVPELEMENT_H
