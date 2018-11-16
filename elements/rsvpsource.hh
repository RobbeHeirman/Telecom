
#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include "rsvp_structs.hh"

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
    RSVPSource();
    ~RSVPSource();

    const char* class_name() const { return "RSVPSource"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return PULL; }

    WritablePacket* generate_path();
    WritablePacket* generate_resv();
    WritablePacket* generate_path_err();
    WritablePacket* generate_resv_err();
    WritablePacket* generate_path_tear();
    WritablePacket* generate_resv_tear();
    WritablePacket* generate_resv_conf();

    static void complete_header(WritablePacket*, unsigned int);

    Packet* pull(int);

    static int send(const String&, Element*, void*, ErrorHandler*);
    void add_handlers();

private:
    char m_send;

    static unsigned int const s_headroom {sizeof(click_ether)
                                        + sizeof(click_ip)
                                        + sizeof(click_udp)};
};

CLICK_ENDDECLS

#endif // CLICK_RSVPSOURCE_HH
