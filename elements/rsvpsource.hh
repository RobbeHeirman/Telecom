
#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include "rsvpheaders.hh"
#include <string.h>
#include <click/error.hh>
#include <click/element.hh>

CLICK_DECLS

class RSVPSource: public Element
{
public:
    RSVPSource();
    ~RSVPSource();

    const char* class_name() const { return "RSVPSource"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return PULL; }

    static unsigned char* write_header(unsigned char* packet,
                                       RSVPType       message_type,
                                       uint8_t        send_ttl);

    static unsigned char* add_session(unsigned char*   packet,
                                      uint32_t         destination_address,
                                      uint8_t          protocol,
                                      uint16_t         destination_port = 0x0000,
                                      RSVPSessionFlags flags = RSVPSessionFlags::NONE);

    static unsigned char* add_rsvp_hop(unsigned char* packet,
                                       uint32_t       address,
                                       uint32_t       lih = 0x00000000);

    static unsigned char* add_time_values(unsigned char* packet,
                                          uint32_t       refresh);

    static unsigned char* add_sender_template(unsigned char* packet,
                                              uint32_t       source_address,
                                              uint16_t       source_port = 0x0000);

    static unsigned char* add_sender_tspec(unsigned char* packet,
                                           float          r,
                                           float          b,
                                           float          p,
                                           uint32_t       m,
                                           uint32_t       M);

    Packet* pull(int);

    static int send(const String&, Element*, void*, ErrorHandler*);

    void add_handlers();

private:
    bool m_send;
};

CLICK_ENDDECLS

#endif // CLICK_RSVPSOURCE_HH
