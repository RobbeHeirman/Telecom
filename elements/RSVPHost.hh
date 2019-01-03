
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
    struct PathState;

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

    // Packet parsers
    void parse_path(const unsigned char* packet);
    void parse_resv(const unsigned char* packet);
    void parse_path_err(const unsigned char* packet);
    void parse_resv_err(const unsigned char* packet);
    void parse_path_tear(const unsigned char* packet);
    void parse_resv_tear(const unsigned char* packet);
    void parse_resv_conf(const unsigned char* packet);

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

    // Utility functions
    static void clear_state(PathState& state);

private:
    // Timer callback data
    struct SendData
    {
        RSVPHost* host;
        SessionID session_id;
        SenderID sender_id;
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

    // The current sessions
    struct PathState
    {
        IPAddress prev_hop;
        Vector<RSVPPolicyData> policy_data;
        RSVPSenderTSpec t_spec;

        Timer* timeout_timer;
        Timer* refresh_timer;

        TearData* tear_data;
        SendData* send_data;

        bool confirmed {false};
    };
    typedef HashMap<uint64_t, PathState> StateMap;

    struct SessionStates
    {
        StateMap senders;
        StateMap receivers;
    };
    typedef HashMap<uint64_t, SessionStates> SessionStatesMap;
    SessionStatesMap m_sessions;

    typedef HashMap<int, uint64_t> SessionIDMap;
    SessionIDMap m_session_ids;

    // Default values for RSVP messages
    static constexpr float s_bucket_rate {10000};
    static constexpr float s_bucket_size {1000};
    static constexpr float s_peak_rate {100000};
    static constexpr uint32_t s_min_unit {100};
    static constexpr uint32_t s_max_size {1500};

    static constexpr uint32_t R {10000};    // TODO set to 30000 (10000 for testing)
    static constexpr uint8_t K {3};
};


CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH
