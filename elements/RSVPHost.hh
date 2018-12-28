
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include "../../ip/ipencap.hh"
#include "RSVPStructs.hh"

#include <string.h>
#include <sys/types.h>
#include <click/timer.hh>
#include <click/error.hh>
#include <click/element.hh>
#include <clicknet/ether.h>
#include <click/hashmap.hh>

CLICK_DECLS

// Struct and typedef to keep track of all current sessions
struct Session
{
    // Destination data
    in_addr destination_address;
    uint16_t destination_port;

    // Source data
    in_addr source_address;
    uint16_t source_port;

    // Hop data
    in_addr hop_address;

    // Timers for sending Path/Resv messages and the local state's lifetime
    Timer* send;
    Timer* lifetime;
};
typedef HashMap<int, Session> SessionMap;

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
    WritablePacket* generate_path(int session_id);
    WritablePacket* generate_resv(int session_id, bool need_confirm);
    WritablePacket* generate_path_err(int session_id);
    WritablePacket* generate_resv_err(int session_id);
    WritablePacket* generate_path_tear(int session_id);
    WritablePacket* generate_resv_tear(int session_id);
    WritablePacket* generate_resv_conf(int session_id);
    static void complete_header(WritablePacket* packet, int size);

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
        int session_id;
    };
    struct ResvData
    {
        RSVPHost* host;
        int session_id;
        bool confirm;
    };
    struct ReleaseData
    {
        RSVPHost* host;
        int session_id;
    };

    // Timer callback functions
    static void push_path(Timer* timer, void* user_data);
    static void push_resv(Timer* timer, void* user_data);
    static void release_session(Timer* timer, void* user_data);

    // Function that sets the source and destination address in the IPEncap element
    void set_ipencap(const in_addr& source, const in_addr& destination);

    // Handler functions
public:
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
    HashMap<int, Session> m_sessions;

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
