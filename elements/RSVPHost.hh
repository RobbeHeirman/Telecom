
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include "RSVPElement.hh"
#include "RSVPStructs.hh"

#include <string.h>
#include <sys/types.h>
#include <click/error.hh>
#include <click/element.hh>
#include <click/hashmap.hh>

CLICK_DECLS


class RSVPHost: public RSVPElement
{
public:
    // The constructor and destructor
    RSVPHost();
    ~RSVPHost();

    // Standard click information functions
    const char* class_name() const { return "RSVPHost"; }
    const char* port_count() const { return "0-1/1"; }
    const char* processing() const { return PUSH; }

    // Standard click functions
    int configure(Vector<String>& config, ErrorHandler* errh);
    void push(int, Packet*);

    // Packet generators
    WritablePacket* generate_path(const SessionID& session_id, const SenderID& sender_id);
    WritablePacket* generate_resv(const SessionID& session_id, const SenderID& sender_id, bool confirm = false);
    WritablePacket* generate_resv_conf(const SessionID& session_id, const SenderID& sender_id, const Resv& resv);

    // Packet parsers
    void parse_path(const Packet* packet);
    void parse_resv(const Packet* packet);
    void parse_path_err(const Packet* packet);
    void parse_resv_err(const Packet* packet);
    void parse_path_tear(const Packet* packet);
    void parse_resv_tear(const Packet* packet);
    void parse_resv_conf(const Packet* packet);

    // Handler functions
    /// session ID <int>, DST <addr>, PORT <port>[, PROTO <uint8_t>]
    static int session(const String& config, Element* element, void*, ErrorHandler* errh);
    /// sender ID <int>, SRC <addr>, PORT <port>
    static int sender(const String& config, Element* element, void*, ErrorHandler* errh);
    /// reserve ID <int>, CONF <bool>
    static int reserve(const String& config, Element* element, void*, ErrorHandler* errh);
    /// release ID <int>
    static int release(const String& config, Element* element, void*, ErrorHandler* errh);
    void add_handlers();

private:
    // Timer callback data
    struct PathData
    {
        RSVPHost* host;
        SessionID session_id;
        SenderID sender_id;
    };
    struct ResvData
    {
        RSVPHost* host;
        SessionID session_id;
        SenderID sender_id;
        bool confirm;
    };
    struct TearData
    {
        RSVPHost* host;
        SessionID session_id;
        SenderID sender_id;
        bool sender;
    };

    // Timer callback functions
    static void push_path(Timer* timer, void* user_data);
    static void push_resv(Timer* timer, void* user_data);
    static void tear_state(Timer* timer, void* user_data);

    // Structs and typedef to keep track of the senders of a certain session
    struct State
    {
        in_addr hop_address;
        Vector<RSVPPolicyData> policy_data;
        RSVPSenderTSpec sender_tspec;
        Timer* send;
        Timer* lifetime;
    };
    typedef HashMap<uint64_t, State> StateMap;

    // Struct and typedef to keep track of all current sessions
    struct Session
    {
        StateMap senders;
        StateMap receivers;
    };
    typedef HashMap<uint64_t, Session> SessionMap;
    typedef HashMap<int, SessionID> SessionIDMap;

    // The current sessions
    SessionMap m_sessions;
    SessionIDMap m_session_ids;

    // The refresh value for RSVPTimeValues objects
    static constexpr uint32_t s_refresh {10000};

    // Values for RSVPSenderTSpec objects
    static constexpr float s_bucket_rate {10000};
    static constexpr float s_bucket_size {1000};
    static constexpr float s_peak_rate {100000};
    static constexpr uint32_t s_min_unit {100};
    static constexpr uint32_t s_max_size {1500};
};


CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH
