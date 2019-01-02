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
private:

    struct ReserveCallbackData {
        RSVPNode* me;

        uint64_t sender_key;
        uint64_t session_key;
    };


    // Used to bookkeep Reservation state
    struct ReserveState {

        ~ReserveState(){
            delete refresh_timer;
            delete timeout_timer;
            delete call_back_data;
        }
        RSVPSession session;
        IPAddress next_hop; // set in reservation state
        RSVPFlowSpec flowSpec;
        RSVPFilterSpec filterSpec;
        float R;
        float L;

        bool is_timeout = true;
        Timer* refresh_timer{nullptr};
        Timer* timeout_timer{nullptr};
        ReserveCallbackData* call_back_data{nullptr}; // Needed to cleanly remove
    };

    /**
     * Wille handle accordingly if a message is a path message.
     * @param p
     */
    void handle_path_message(Packet* p, int port);
    void handle_resv_message(Packet* p, int port);
    bool handle_path_tear_message(Packet* p, int port);
    bool handle_resv_tear_message(Packet* p, int port);
    bool handle_path_error_message(Packet* p, int port);// TODO: from here
    bool handle_resv_error_message(Packet* p, int port);
    bool handle_confirmation_message(Packet* p, int port); // Till here

    // deleting states
    bool delete_state(const uint64_t& sender_key, const uint64_t& session_key, const in_addr& addr, bool path = true);
    bool delete_state(const uint64_t& sender_key, const uint64_t& session_key);
    bool delete_ff_rsv_state(const uint64_t& sender_key, const uint64_t& session_key);

    // Checking states
    bool path_state_exists(const uint64_t& sender_key, const uint64_t& session_key);
    bool resv_ff_exists(const uint64_t& sender_key, const uint64_t& session_key);


    //Calculate values
    float calculate_refresh(float r);
    float calculate_L(float r);


    // Timer Callback functions
    static void handle_path_refresh(Timer* timer, void* data);
    static void handle_path_time_out(Timer* timer, void* data);
    static void handle_reserve_refresh(Timer* timer, void* data);
    static void handle_reserve_time_out(Timer* timer, void* data);

    //Refresh and timeout states
    void refresh_path_state(uint64_t sender, uint64_t session, Timer* t);
    void time_out_path_state(uint64_t sender, uint64_t session, Timer* t);
    void refresh_reserve_state(uint64_t sender, uint64_t session, Timer* t);
    void time_out_reserve_state(uint64_t sender, uint64_t session, Timer* t);

    //Some packet generation
    WritablePacket* generate_path(PathState* state);
    WritablePacket* generate_resv(ReserveState& r_state);

private:
    Vector<IPAddress> m_interfaces;
    HashTable<uint64_t, HashTable <uint64_t, ReserveState>> m_ff_resv_states;
    unsigned int K = 3; //Constant with default 3 (see RFC)
};

CLICK_ENDDECLS

#endif //TELECOM_RSVPNODEPATH_H
