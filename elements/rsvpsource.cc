
#include <click/config.h>
#include "rsvpsource.hh"
#include <sys/types.h>
#include <click/glue.hh>
#include <clicknet/udp.h>
#include <clicknet/ether.h>

CLICK_DECLS

RSVPSource::RSVPSource(): m_send(true) {}

RSVPSource::~RSVPSource() = default;

Packet* RSVPSource::pull(int) {

    if (not m_send)
        return nullptr;
    m_send = false;

    unsigned const headroom {sizeof(click_ip)
                             + sizeof(click_udp)
                             + sizeof(click_ether)};
    unsigned const packetsize {sizeof(RSVPHeader)
                               + sizeof(RSVPSession)
                               + sizeof(RSVPHop)
                               + sizeof(RSVPTimeValues)
                               + sizeof(RSVPSenderTemplate)
                               + sizeof(RSVPSenderTSpec)};
    unsigned const tailroom {0};

    WritablePacket* const packet {Packet::make(headroom, nullptr, packetsize, tailroom)};
    if (packet == nullptr)
        return nullptr;
    memset(packet->data(), 0, packetsize);

    auto* loc {packet->data()};
    loc = RSVPHeader::write(loc, RSVPHeader::Path, 0xff);
    loc = RSVPSession::write(loc, 0x0f0f0f0f, 0x11, 0x4321);
    loc = RSVPHop::write(loc, 0x01234567);
    loc = RSVPTimeValues::write(loc, 0x0000ffff);
    loc = RSVPSenderTemplate::write(loc, 0x01234567, 0x1234);
    loc = RSVPSenderTSpec::write(loc, 1, 1, 1, 1234, 4321);

    auto* const header {(RSVPHeader*) packet->data()};
    header->length = htons(packetsize);
    header->checksum = click_in_cksum(packet->data(), packetsize);

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
