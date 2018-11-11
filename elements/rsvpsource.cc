
#include <click/config.h>
#include "rsvpsource.hh"
#include "rsvpheaders.hh"
#include <click/glue.hh>
#include <sys/types.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>

CLICK_DECLS

RSVPSource::RSVPSource(): m_send(true) {}

RSVPSource::~RSVPSource() = default;

Packet* RSVPSource::pull(int) {

    if (not m_send)
        return nullptr;
    m_send = false;

    unsigned int const headroom {sizeof(click_ip)
                                 + sizeof(click_udp)
                                 + sizeof(click_ether)};
    unsigned int const tailroom {0};
    unsigned int const packetsize {sizeof(RSVPHeader)
                                   + sizeof(RSVPSession)
                                   + sizeof(RSVPHop)
                                   + sizeof(RSVPTimeValues)
                                   + sizeof(RSVPSenderTemplate)
                                   + sizeof(RSVPSenderTspec)};

    click_chatter(String(headroom).c_str());

    WritablePacket* const packet {Packet::make(headroom, nullptr, packetsize, tailroom)};
    if (packet == nullptr)
        return nullptr;
    memset(packet->data(), 0, packetsize);

    auto* loc {packet->data()};
    auto* const header {(RSVPHeader*) loc};
    header->version     = 1;
    header->msg_type    = RSVP_TYPE_PATH;
    header->send_ttl    = 255;
    header->length      = packetsize;

    loc += sizeof(RSVPHeader);
    auto* const session {(RSVPSession*) loc};
    session->length     = sizeof(RSVPSession);
    session->class_num  = RSVP_CLASS_SESSION;
    session->c_type     = 1;
    session->dest_addr  = 0x01010101;
    session->protocol   = 1;

    loc += sizeof(RSVPSession);
    auto* const rsvphop {(RSVPHop*) loc};
    rsvphop->length     = sizeof(RSVPHop);
    rsvphop->class_num  = RSVP_CLASS_RSVPHOP;
    rsvphop->c_type     = 1;
    rsvphop->address    = 0x02020202;

    loc += sizeof(RSVPHop);
    auto* const times {(RSVPTimeValues*) loc};
    times->length       = sizeof(RSVPTimeValues);
    times->class_num    = RSVP_CLASS_TIME_VALUES;
    times->c_type       = 1;
    times->refresh      = 0x0000ffff;

    loc += sizeof(RSVPTimeValues);
    auto* const send_templ {(RSVPSenderTemplate*) loc};
    send_templ->length      = sizeof(RSVPSenderTemplate);
    send_templ->class_num   = RSVP_CLASS_SENDER_TEMPLATE;
    send_templ->c_type      = 1;
    send_templ->src_addr    = 0x02020202;

    loc += sizeof(RSVPSenderTemplate);
    auto* const tspec {(RSVPSenderTspec*) loc};
    tspec->length       = sizeof(RSVPSenderTspec);
    tspec->class_num    = RSVP_CLASS_SENDER_TSPEC;
    tspec->c_type       = 2;

    header->checksum = click_in_cksum((unsigned char*) packet, packetsize);
    return packet;
}

int RSVPSource::send(const String& s, Element* e, void* vparam, ErrorHandler* errh) {

    auto* const source {(RSVPSource*) e};
    source->m_send = true;
    return 0;
}

void RSVPSource::add_handlers() {

    add_data_handlers("send", Handler::f_read, &m_send);
    add_write_handler("send", send, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
