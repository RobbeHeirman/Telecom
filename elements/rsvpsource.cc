
#include <click/config.h>
#include "rsvpsource.hh"
#include <sys/types.h>
#include <click/glue.hh>
#include <clicknet/udp.h>
#include <clicknet/ether.h>

CLICK_DECLS

RSVPSource::RSVPSource(): m_send(true) {}

RSVPSource::~RSVPSource() = default;

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::write_header(unsigned char* const packet,
                                        RSVPType const message_type,
                                        uint8_t const send_ttl) {

    auto* const header {(RSVPHeader*) packet};
    header->version     = RSVP_VERSION;
    header->msg_type    = message_type;
    header->send_ttl    = send_ttl;
    return packet + sizeof(RSVPHeader);
}

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::add_session(unsigned char* const packet,
                                       uint32_t const destination_address,
                                       uint8_t  const protocol,
                                       uint16_t const destination_port,
                                       RSVPSessionFlags const flags) {

    auto* const session {(RSVPSession*) packet};
    session->length     = sizeof(RSVPSession);
    session->class_num  = RSVPClass::SESSION;
    session->c_type     = 0x01;
    session->dest_addr  = destination_address;
    session->protocol   = protocol;
    session->flags      = flags;
    session->dest_port  = destination_port;
    return packet + sizeof(RSVPSession);
}

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::add_rsvp_hop(unsigned char* const packet,
                                        uint32_t const address,
                                        uint32_t const lih) {

    auto* const rsvp_hop {(RSVPHop*) packet};
    rsvp_hop->length    = sizeof(RSVPHop);
    rsvp_hop->class_num = RSVPClass::HOP;
    rsvp_hop->c_type    = 0x01;
    rsvp_hop->address   = address;
    rsvp_hop->lih       = lih;
    return packet + sizeof(RSVPHop);
}

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::add_time_values(unsigned char* const packet,
                                           uint32_t const refresh) {

    auto* const time_values {(RSVPTimeValues*) packet};
    time_values->length     = sizeof(RSVPTimeValues);
    time_values->class_num  = RSVPClass::TIME_VALUES;
    time_values->c_type     = 0x01;
    time_values->refresh    = refresh;
    return packet + sizeof(RSVPTimeValues);
}

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::add_sender_template(unsigned char* const packet,
                                               uint32_t const source_address,
                                               uint16_t const source_port) {

    auto* const s_template {(RSVPSenderTemplate*) packet};
    s_template->length      = sizeof(RSVPSenderTemplate);
    s_template->class_num   = RSVPClass::SENDER_TEMPLATE;
    s_template->c_type      = 0x01;
    s_template->src_addr    = source_address;
    s_template->src_port    = source_port;
    return packet + sizeof(RSVPSenderTemplate);
}

// packet is a pointer to the place the session object should be added
// returns a pointer after the added object, where the next object should be placed
unsigned char* RSVPSource::add_sender_tspec(unsigned char* const packet,
                                            float const          r,
                                            float const          b,
                                            float const          p,
                                            uint32_t const       m,
                                            uint32_t const       M) {

    auto* const s_tspec {(RSVPSenderTspec*) packet};
    s_tspec->length                     = sizeof(RSVPSenderTspec);
    s_tspec->class_num                  = RSVPClass::SENDER_TSPEC;
    s_tspec->c_type                     = 0x02;
    s_tspec->version                    = 0x0;
    s_tspec->length                     = 0x0007;
    s_tspec->service_header.service_nr  = 0x01;
    s_tspec->service_header.length      = 0x0006;
    s_tspec->param_header.param_nr      = 0x7f;
    s_tspec->param_header.length        = 0x0005;
    s_tspec->r                          = r;
    s_tspec->b                          = b;
    s_tspec->p                          = p;
    s_tspec->m                          = m;
    s_tspec->M                          = M;
    return packet + sizeof(RSVPSenderTspec);
}

Packet* RSVPSource::pull(int) {

    if (not m_send)
        return nullptr;
    m_send = false;

    unsigned int const headroom {sizeof(click_ip) + sizeof(click_udp) + sizeof(click_ether)};
    unsigned int const packetsize {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPHop)
            + sizeof(RSVPTimeValues) + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTspec)};
    unsigned int const tailroom {0};

    WritablePacket* const packet {Packet::make(headroom, nullptr, packetsize, tailroom)};
    if (packet == nullptr)
        return nullptr;
    memset(packet->data(), 0, packetsize);

    auto* loc {packet->data()};
    loc = write_header(loc, RSVPType::PATH, 0xff);
    loc = add_session(loc, 0x0f0f0f0f, 0x11);
    loc = add_rsvp_hop(loc, 0x0f0f0f0f);
    loc = add_time_values(loc, 0xff00ff00);
    loc = add_sender_template(loc, 0xf0f0f0f0, 0x1234);
    loc = add_sender_tspec(loc, 0.45, 0.45, 0.45, 0xf0f0f0f0, 0xf0f0f0f0);

    auto* const header {(RSVPHeader*) packet->data()};
    header->length = packetsize;
    header->checksum = click_in_cksum((unsigned char*) packet, packetsize);

    return packet;
}

int RSVPSource::send(const String& s, Element* e, void* vparam, ErrorHandler* errh) {

    auto* const source {(RSVPSource*) e};
    source->m_send = true;
    return 0;
}

void RSVPSource::add_handlers() {

    add_write_handler("send", send, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
