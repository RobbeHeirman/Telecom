
#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include "RSVPStructs.hh"

#include <string.h>
#include <click/error.hh>
#include <click/element.hh>

#include <clicknet/udp.h>
#include <clicknet/ether.h>
#include <click/hashmap.hh>

CLICK_DECLS

class RSVPSource: public Element
{
public:
    /// The constructor and destructor.
    RSVPSource();
    ~RSVPSource();

    /// Basic click element functions.
    const char* class_name() const { return "RSVPSource"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return AGNOSTIC; }

    /// Functions that generate the different types of packets.
    WritablePacket* generate_path();
    WritablePacket* generate_resv();
    WritablePacket* generate_path_err();
    WritablePacket* generate_resv_err();
    WritablePacket* generate_path_tear();
    WritablePacket* generate_resv_tear();
    WritablePacket* generate_resv_conf();

    /// Function that fills in the header length and checksum.
    static void complete_header(WritablePacket*, unsigned int);

    /// The push and pull functions, as this is an agnostic element.
    void push(int, Packet*);
    Packet* pull(int);

    /// Handler function that uses m_send to
    static int send(const String&, Element*, void*, ErrorHandler*);

    /// The handler functions.
    void add_handlers();

private:
    /// Contains a code for the type of packet that should be sent on the next pull.
    char m_send;

    /// A static value that contains the amount of headroom needed for these 3 headers.
    static unsigned int const s_headroom {sizeof(click_udp) + sizeof(click_ip) + sizeof(click_ether)};
};

CLICK_ENDDECLS

#endif // CLICK_RSVPSOURCE_HH
