//
// Created by robbe on 29/12/18.
//

#ifndef TELECOM_RSVPELEMENT_H
#define TELECOM_RSVPELEMENT_H

#include <click/hashtable.hh>
#include "../ip/ipencap.hh"
#include <clicknet/ether.h>
#include <click/element.hh>
#include <click/vector.hh>
#include "RSVPStructs.hh"
#include <click/error.hh>
#include <click/timer.hh>



CLICK_DECLS

class RSVPNode;
/**
 * Stores a sender template; similar to RSVPSenderTemplate but without the headers
 *
 * @warning source_port is expected to be in the endianness used by the host. The constructor will not convert this, so
 *  in case this needs to be converted the function ntohs should be used beforehand. The to_key functions will however
 *  assume the corresponding port value is in the network's representation, in this case the bytes will be reversed if
 *  necessary.
 */
struct SenderID
{
    in_addr source_address;
    uint16_t _ {0};     // 2 bytes padding
    uint16_t source_port;   // the host representation of the port (endianness)

    // Constructors
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
     *
     * @warning This function assumes the SenderTemplate object has its port in the representation used by the network.
     *  This means that if the object wasn't extracted from a network packet source_port might not have its bytes in the
     *  right order. If that is the case, either use the htons function or simply use SenderID's constructor.
     */
    static inline uint64_t to_key(RSVPSenderTemplate sender) {

        // Make sure the 2 unused bytes are always 0 and that the RSVP object header isn't included in the key
        sender._ = 0;
        sender.src_port = ntohs(sender.src_port);
        return *(uint64_t*)((RSVPObject*)(&sender) + 1);
    }

    /**
     * Turns a FilterSpec object into a key usable in maps, tables...
     */
    static inline uint64_t to_key(RSVPFilterSpec sender) {

        sender._ = 0;
        sender.src_port = ntohs(sender.src_port);
        return *(uint64_t*)((RSVPObject*)(&sender) + 1);
    }

    /**
     * Turns a key into a SessionID object
     */
    static inline SenderID from_key(const uint64_t key) {

        return *(SenderID*)(&key);
    }

    static inline SenderID from_rsvp_sendertemplate(RSVPSenderTemplate* send){
        return from_key(to_key(*send));
    }
};


/**
 * Stores a session; similar to RSVPSession but without the header
 */
struct SessionID
{
    in_addr destination_address;
    uint8_t proto;
    uint8_t _ {0};  // 1 byte padding
    uint16_t destination_port;

    // Constructors
    SessionID(): destination_address {0}, proto {0}, destination_port {0} {}
    SessionID(const in_addr address, const uint16_t port, const uint8_t proto)
            : destination_address {address}, proto {proto}, destination_port {port} {}

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

        // Make sure the flags are always 0 and that the port is in the correct endianness
        session.flags = RSVPSession::None;
        session.dest_port = ntohs(session.dest_port);
        return *(uint64_t*)((RSVPObject*)(&session) + 1);
    }

    /**
     * Turns a key into a SessionID object
     */
    static inline SessionID from_key(const uint64_t key) {

        return *(SessionID*)(&key);
    }

    static inline SessionID from_rsvp_session(const RSVPSession* ses){

        return from_key(to_key(*ses));
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
    bool find_path_ptrs(const unsigned char* packet, Path& path);

    /**
     * Helper function that will help us find object in RESV messages
     * @param packet a pointer to the packet containing the RESV message
     * @return whether all objects were found successfully
     */
    bool find_resv_ptrs(const unsigned char* packet, Resv& resv);

    /**
     * Helper function that will help us find objects in PATH_ERR messages
     * @param packet a pointer to the packet containing the PATH_ERR message
     * @return whether all objects were successfully found
     */
    bool find_path_err_ptrs(const unsigned char* packet, PathErr& path_err);

    /**
     * Helper function that will help us find objects in RESV_ERR messages
     *
     * RESV_ERR messages only contain one flow_descriptor
     * in this implementation Scope objects in RESV_ERR messages can be ignored
     *
     * @param packet a pointer to the packet containing the RESV_ERR message
     * @return whether all objects were successfully found
     */
    bool find_resv_err_ptrs(const unsigned char* packet, ResvErr& resv_err);

    /**
     * Helper function that will help us find objects in PATH_TEAR messages
     *
     * In PATH_TEAR messages sender TSpec objects should be ignored
     *
     * @param packet a pointer to the packet containing the PATH_TEAR message
     * @return whether all objects were successfully found
     */
    bool find_path_tear_ptrs(const unsigned char* packet, PathTear& path_tear);

    /**
     * Helper function that will help us find objects in RESV_TEAR messages
     *
     * In RESV_TEAR messages a Scope object and FlowSpec objects should be ignored
     *
     * @param packet a pointer to the packet containing the RESV_TEAR message
     * @return whether all objects were successfully found
     */
    bool find_resv_tear_ptrs(const unsigned char* packet, ResvTear& resv_tear);

    /**
     * Helper function that will help us find objects in RESV_CONF messages
     *
     * @param packet a pointer to the packet containing the RESV_CONF message
     * @return whether all objects were successfully found
     */
    bool find_resv_conf_ptrs(const unsigned char* packet, ResvConf& resv_conf);

    /**
     * Helper function that checks whether there is an Integrity object and skips it (as well as the header)
     *
     * @param packet a pointer to the packet containg the RSVP message
     * @return a pointer to the first RSVP object that is not an Integrity object
     */
    RSVPObject* skip_integrity(const unsigned char* packet) const;

    /**
     * Helper function that creates a new PATH packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path(const SessionID& session_id, const SenderID& sender_id, uint32_t R,
                                  const RSVPSenderTSpec& t_spec);

    /**
     * Helper function that creates a new RESV function
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     * @param confirm
     * @return
     */
    WritablePacket* generate_resv(const SessionID& session_id, const SenderID& sender_id, uint32_t R,
                                  const RSVPSenderTSpec& t_spec, bool confirm);

    /**
     * Helper function that creates a new PATH_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_err(const SessionID& session_id, const SenderID& sender_id,
                                      const RSVPSenderTSpec& t_spec, RSVPErrorSpec::ErrorCode code,
                                      uint16_t error_value);

    /**
     * Helper function that creates a new RESV_ERR packet
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_err(const SessionID& session_id, const SenderID& sender_id,
                                      const RSVPSenderTSpec& t_spec,
                                      RSVPErrorSpec::ErrorCode = RSVPErrorSpec::ErrorCode::Confirmation,
                                      uint16_t error_value = 0);

    /**
     * Helper function that creates a new PATH_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_path_tear(const SessionID& session_id, const SenderID& sender_id,
                                       const RSVPSenderTSpec& t_spec);

    /**
     * Helper function that creates a new RESV_TEAR message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_tear(const SessionID& session_id, const SenderID& sender_id);

    /**
     * Helper function that creates a new RESV_CONF message
     * @param session_id: contains session data
     * @param sender_id: contains sender template data
     */
    WritablePacket* generate_resv_conf(const SessionID& session_id, const SenderID& sender_id,
                                       const RSVPSenderTSpec& t_spec, const RSVPResvConfirm& resv_confirm);

    /**
     * Function that sets the source and destination address in the IPEncap element
     */
    void ipencap(Packet* packet, const in_addr& source, const in_addr& destination);

    /**
     * Function that sends an error to the default handler if the condition is true
     */
    static inline bool check(bool condition, const String& message) {

        if (condition) {
            ErrorHandler::default_handler()->error(message.c_str());
        }
        return condition;
    }

    /**
     * Functions that converts a session & sender object package to a uint64 So we can use this as a key for session
     * bookkeeping.
     */
    uint64_t session_to_key(RSVPSession* session);
    uint64_t sender_template_to_key(RSVPSenderTemplate* sender_template);


    struct PathCallbackData {
        RSVPNode* me;
        uint64_t sender_key;
        uint64_t session_key;
    };

    /**
     * PathState is a struct for bookkeeping of the RSVP path sof state.
     * @member: prev_hop, notes the IP Unicast address of the prev hop, will be found in hop object of rsvp message.
     */

    struct PathState{

        ~PathState(){
            delete refresh_timer;
            delete timeout_timer;
            delete path_call_back_data;
        }

        // Keys of state in the HashMap, timer functions need those
        RSVPSenderTemplate sender_template;
        RSVPSession session;

        IPAddress prev_hop; // prev_hop node
        Vector<RSVPPolicyData> policy_data; // Potential policy data
        RSVPSenderTSpec t_spec; // TSpec element

        //If timeout timer passes if this is true then the pathState timed out and should be deleted
        bool is_timeout = true;

        float R;
        float L;

        // Keeping the timer ptr's so we can free them from the heap
        Timer* refresh_timer{nullptr};
        Timer* timeout_timer{nullptr};
        PathCallbackData* path_call_back_data;

    };

    typedef HashTable<uint64_t, HashTable<uint64_t, PathState>> PathStateMap;
    PathStateMap m_path_state;

    // needs to place his ip address in next hop.
    IPAddress m_address_info;

    // The headroom needed for an ether and ip header
    static constexpr unsigned int s_headroom {sizeof(click_ip) + 4 + sizeof(click_ether)};
};

CLICK_ENDDECLS

#endif //TELECOM_RSVPELEMENT_H
