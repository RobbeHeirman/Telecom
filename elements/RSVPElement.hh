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
 * Stores a sender template; similar to RSVPSenderTemplate but without the headers
 */
struct SenderID
{
    in_addr source_address;
    uint16_t _ {0};     // 2 bytes padding
    uint16_t source_port;

    SenderID(): source_address {0}, source_port {0} {}
    SenderID(const in_addr address, const uint16_t port): source_address {address}, source_port {port} {}

    /**
     * Turns a SenderID object into a key usable in maps, tables...
     */
    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }

    /**
     * Turns a SenderTemplate object into a key usable in maps, tables...
     */
    static inline uint64_t to_key(RSVPSenderTemplate sender) {

        // Make sure the 2 unused bytes are always 0 and that the RSVP object header isn't included in the key
        sender._ = 0;
        return *(uint64_t*)((RSVPObject*)(&sender) + 1);
    }

    /**
     * Turns a key into a SessionID object
     */
    static inline SenderID from_key(const uint64_t key) {

        return *(SenderID*)(&key);
    }
};


/**
 * Stores a session; similar to RSVPSession but without the header
 */
struct SessionID
{
    in_addr destination_address;
    uint16_t destination_port;
    uint8_t _ {0};  // 1 byte padding
    uint8_t proto;

    SessionID(): destination_address {0}, destination_port {0}, proto {0} {}
    SessionID(const in_addr address, const uint16_t port, const uint8_t proto)
            : destination_address {address}, destination_port {port}, proto {proto} {}

    /**
     * Turns a SessionID object into a key usable in maps, tables...
     */
    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }

    /**
     * Turns a Session object into a key usable in maps, tables...
     */
    static inline uint64_t to_key(RSVPSession session) {

        // Make sure the flags are always 0 and that the RSVP object header isn't included in the key
        session.flags = RSVPSession::None;
        return *(uint64_t*)((RSVPObject*)(&session) + 1);
    }

    /**
     * Turns a key into a SessionID object
     */
    static inline SessionID from_key(const uint64_t key) {

        return *(SessionID*)(&key);
    }
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
    bool find_path_ptrs(const Packet* packet, Path& path);

    /**
     * Helper function that will help us find object in RESV messages
     * @param packet a pointer to the packet containing the RESV message
     * @return whether all objects were found successfully
     */
    bool find_resv_ptrs(const Packet* packet, Resv& resv);

    /**
     * Helper function that will help us find objects in PATH_ERR messages
     * @param packet a pointer to the packet containing the PATH_ERR message
     * @return whether all objects were successfully found
     */
    bool find_path_err_ptrs(const Packet* packet, PathErr& path_err);

    /**
     * Helper function that will help us find objects in RESV_ERR messages
     *
     * RESV_ERR messages only contain one flow_descriptor
     * in this implementation Scope objects in RESV_ERR messages can be ignored
     *
     * @param packet a pointer to the packet containing the RESV_ERR message
     * @return whether all objects were successfully found
     */
    bool find_resv_err_ptrs(const Packet* packet, ResvErr& resv_err);

    /**
     * Helper function that will help us find objects in PATH_TEAR messages
     *
     * In PATH_TEAR messages sender TSpec objects should be ignored
     *
     * @param packet a pointer to the packet containing the PATH_TEAR message
     * @return whether all objects were successfully found
     */
    bool find_path_tear_ptrs(const Packet* packet, PathTear& path_tear);

    /**
     * Helper function that will help us find objects in RESV_TEAR messages
     *
     * In RESV_TEAR messages a Scope object and FlowSpec objects should be ignored
     *
     * @param packet a pointer to the packet containing the RESV_TEAR message
     * @return whether all objects were successfully found
     */
    bool find_resv_tear_ptrs(const Packet* packet, ResvTear& resv_tear);

    /**
     * Helper function that will help us find objects in RESV_CONF messages
     *
     * @param packet a pointer to the packet containing the RESV_CONF message
     * @return whether all objects were successfully found
     */
    bool find_resv_conf_ptrs(const Packet* packet, ResvConf& resv_conf);

    /**
     * Helper function that checks whether there is an Integrity object and skips it (as well as the header)
     *
     * @param packet a pointer to the packet containg the RSVP message
     * @return a pointer to the first RSVP object that is not an Integrity object
     */
    RSVPObject* skip_integrity(const Packet* packet) const;

    /**
     * Helper function that creates a new PATH_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_err(const SessionID& session_id, const SenderID& sender_id);

    /**
     * Helper function that creates a new RESV_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_err(const SessionID& session_id, const SenderID& sender_id);

    /**
     * Helper function that creates a new PATH_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_tear(const SessionID& session_id, const SenderID& sender_id);

    /**
     * Helper function that creates a new RESV_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_tear(const SessionID& session_id, const SenderID& sender_id);

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
