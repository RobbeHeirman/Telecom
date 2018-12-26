
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

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
    in_addr destination_address;
    uint16_t destination_port;
    in_addr source_address;
    uint16_t source_port;
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
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return PUSH; }

    // Standard click functions
    int configure(Vector<String>&, ErrorHandler*);
    void push(int, Packet*);

    // Packet generators
    WritablePacket* generate_path(int);
    WritablePacket* generate_resv(int);
    WritablePacket* generate_path_err(int);
    WritablePacket* generate_resv_err(int);
    WritablePacket* generate_path_tear(int);
    WritablePacket* generate_resv_tear(int);
    WritablePacket* generate_resv_conf(int);
    static void complete_header(WritablePacket*, int);

    // Timer callback data and function
private:
    struct TimerData
    {
        RSVPHost* host;
        int session_id;
    };
    static void push_path(Timer*, void*);

    // Handler functions
public:
    /// session ID <int>, DST <addr>, PORT <port>
    static int session(const String&, Element*, void*, ErrorHandler*);
    /// sender ID <int>, SRC <addr>, PORT <port>
    static int sender(const String&, Element*, void*, ErrorHandler*);
    /// reserve ID <int>, CONF <int?>
    static int reserve(const String&, Element*, void*, ErrorHandler*);
    /// release ID <int>
    static int release(const String&, Element*, void*, ErrorHandler*);
    void add_handlers();

private:
    // The current sessions
    HashMap<int, Session> m_sessions;

    // The headroom needed for an ether and ip header
    static constexpr unsigned int s_headroom {sizeof(click_ip) + sizeof(click_ether)};

    // The refresh value for RSVPTimeValues objects
    static constexpr uint32_t s_refresh {10000};

    // Values for RSVPSenderTSpec objects
    static constexpr float s_bucket_rate {0.0};
    static constexpr float s_bucket_size {0.0};
    static constexpr float s_peak_rate {0.0};
    static constexpr uint32_t s_max_unit {0};
    static constexpr uint32_t s_max_size {0};
};

CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH
