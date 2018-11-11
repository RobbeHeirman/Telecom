
#include <click/config.h>
#include "rsvpsource.hh"
#include "rsvpheaders.hh"
#include <click/glue.hh>
#include <sys/types.h>
#include <clicknet/udp.h>
#include <clicknet/ether.h>

CLICK_DECLS

RSVPSource::RSVPSource(): m_count(0) {}

RSVPSource::~RSVPSource() = default;

Packet* RSVPSource::pull(int) {

    if (m_count == 5)
        return nullptr;

    unsigned int const headroom {sizeof(click_ip) + sizeof(click_udp) + sizeof(click_ether)};
    unsigned int const packetsize {sizeof(RSVPHeader)};
    unsigned int const tailroom {0};

    WritablePacket* const packet {Packet::make(headroom, nullptr, packetsize, tailroom)};
    if (packet == nullptr)
        return nullptr;
    memset(packet->data(), 0, packet->length());

    auto* const header {(RSVPHeader*) packet->data()};
    header->version = 1;
    header->msg_type = RSVP_TYPE_PATH;
    header->send_ttl = 100;
    header->length   = packetsize;
    header->checksum = click_in_cksum((unsigned char*) packet, packetsize);

    m_count++;
    return packet;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
