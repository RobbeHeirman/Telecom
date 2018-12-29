
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include "../ip/ipencap.hh"
#include "RSVPStructs.hh"

#include <string.h>
#include <sys/types.h>
#include <click/timer.hh>
#include <click/error.hh>
#include <click/element.hh>
#include <clicknet/ether.h>
#include <click/hashmap.hh>

CLICK_DECLS


// Structs and typdef to keep track of the senders of a certain session
struct Flow
{
    // The address of the previous/next node
    in_addr hop_address;

    // The timer with which PATH / RESV messages are scheduled
    Timer* send;
};
struct FlowID
{
    in_addr source_address;
    uint16_t source_port;

    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }
};
typedef HashMap<uint64_t, Flow> FlowMap;

// Struct and typedef to keep track of all current sessions
struct Session
{
    // The session's senders and receivers
    FlowMap senders;
    FlowMap receivers;

    // The timer with which the local state's lifetime is measured
    Timer* lifetime;
};
struct SessionID
{
    in_addr destination_address;
    uint16_t destination_port;
    uint8_t proto;

    inline uint64_t to_key() const {

        return *(uint64_t*)(this);
    }
};
typedef HashMap<uint64_t, Session> SessionMap;
typedef HashMap<int, SessionID> SessionIDMap;


class RSVPHost: public Element
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
    WritablePacket* generate_path(const SessionID& session_id, const FlowID& sender_id);
    WritablePacket* generate_resv(const SessionID& session_id, const FlowID& sender_id, bool need_confirm = false);
    WritablePacket* generate_path_err(const SessionID& session_id, const FlowID& sender_id);
    WritablePacket* generate_resv_err(const SessionID& session_id, const FlowID& sender_id);
    WritablePacket* generate_path_tear(const SessionID& session_id, const FlowID& sender_id);
    WritablePacket* generate_resv_tear(const SessionID& session_id, const FlowID& sender_id);
    WritablePacket* generate_resv_conf(const SessionID& session_id, const FlowID& sender_id);

    // Packet parsers
    void parse_path(const unsigned char* message, int size);
    void parse_resv(const unsigned char* message, int size);
    void parse_path_err(const unsigned char* message, int size);
    void parse_resv_err(const unsigned char* message, int size);
    void parse_path_tear(const unsigned char* message, int size);
    void parse_resv_tear(const unsigned char* message, int size);
    void parse_resv_conf(const unsigned char* message, int size);

    // Function that sends an error to the default handler if the condition is true
    static inline bool check(bool condition, const String& message);

private:
    // Timer callback data
    struct PathData
    {
        RSVPHost* host;
        SessionID session_id;
        FlowID sender_id;
    };
    struct ResvData
    {
        RSVPHost* host;
        SessionID session_id;
        FlowID sender_id;
        bool confirm;
    };
    struct ReleaseData
    {
        RSVPHost* host;
        SessionID session_id;
    };

    // Timer callback functions
    static void push_path(Timer* timer, void* user_data);
    static void push_resv(Timer* timer, void* user_data);
    static void release_session(Timer* timer, void* user_data);

    // Function that sets the source and destination address in the IPEncap element
    void set_ipencap(const in_addr& source, const in_addr& destination);

public:
    // Handler functions
    /// session ID <int>, DST <addr>, PORT <port>
    static int session(const String& config, Element* element, void*, ErrorHandler* errh);
    /// sender ID <int>, SRC <addr>, PORT <port>
    static int sender(const String& config, Element* element, void*, ErrorHandler* errh);
    /// reserve ID <int>, CONF <int?>
    static int reserve(const String& config, Element* element, void*, ErrorHandler* errh);
    /// release ID <int>
    static int release(const String& config, Element* element, void*, ErrorHandler* errh);
    void add_handlers();

private:
    // The current sessions
    SessionMap m_sessions;
    SessionIDMap m_session_ids;

    // The IPEncap element that (should) encapsulate any packet sent out by the RSVPHost element
    IPEncap* m_ipencap;

    // The headroom needed for an ether and ip header
    static constexpr unsigned int s_headroom {sizeof(click_ip) + sizeof(click_ether) + 4};

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
