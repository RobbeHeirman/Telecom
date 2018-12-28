
#include <click/config.h>
#include "RSVPSource.hh"

#include <sys/types.h>
#include <click/args.hh>
#include <click/glue.hh>

CLICK_DECLS

RSVPSource::RSVPSource()
        : m_send {' '} {}

RSVPSource::~RSVPSource() = default;

//WritablePacket* RSVPSource::generate_path() {
//
//    unsigned int const size {sizeof(RSVPHeader)     + sizeof(RSVPSession)        + sizeof(RSVPHop)
//                           + sizeof(RSVPTimeValues) + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//    pos_ptr = RSVPHeader        ::write(pos_ptr, RSVPHeader::Path);
//    pos_ptr = RSVPSession       ::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPHop           ::write(pos_ptr, 0x01234567);
//    pos_ptr = RSVPTimeValues    ::write(pos_ptr, 0x0000ffff);
//    pos_ptr = RSVPSenderTemplate::write(pos_ptr, 0x01234567, 1234);
//    pos_ptr = RSVPSenderTSpec   ::write(pos_ptr, 1.5, 2.5, 3.4, 1234, 4321);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_resv() {
//
//    unsigned int const size {sizeof(RSVPHeader)     + sizeof(RSVPSession) + sizeof(RSVPHop)
//                           + sizeof(RSVPTimeValues) + sizeof(RSVPStyle)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader    ::write(pos_ptr, RSVPHeader::Resv);
//    pos_ptr = RSVPSession   ::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPHop       ::write(pos_ptr, 0x01234567);
//    pos_ptr = RSVPTimeValues::write(pos_ptr, 0x0000ffff);
//    pos_ptr = RSVPStyle     ::write(pos_ptr);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_path_err() {
//
//    unsigned int const size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPErrorSpec)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader   ::write(pos_ptr, RSVPHeader::PathErr);
//    pos_ptr = RSVPSession  ::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPErrorSpec::write(pos_ptr, 0x76543210, 0x00);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_resv_err() {
//
//    unsigned int const size{sizeof(RSVPHeader)    + sizeof(RSVPSession) + sizeof(RSVPHop)
//                          + sizeof(RSVPErrorSpec) + sizeof(RSVPStyle)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader   ::write(pos_ptr, RSVPHeader::PathErr);
//    pos_ptr = RSVPSession  ::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPHop      ::write(pos_ptr, 0x01234567);
//    pos_ptr = RSVPErrorSpec::write(pos_ptr, 0x76543210, 0x00);
//    pos_ptr = RSVPStyle    ::write(pos_ptr);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_path_tear() {
//
//    unsigned int const size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPHop)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader ::write(pos_ptr, RSVPHeader::PathTear);
//    pos_ptr = RSVPSession::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPHop    ::write(pos_ptr, 0x01234567);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_resv_tear() {
//
//    unsigned int const size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPHop) + sizeof(RSVPStyle)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader ::write(pos_ptr, RSVPHeader::ResvTear);
//    pos_ptr = RSVPSession::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPHop    ::write(pos_ptr, 0x01234567);
//    pos_ptr = RSVPStyle  ::write(pos_ptr);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//WritablePacket* RSVPSource::generate_resv_conf() {
//
//    unsigned int const size{sizeof(RSVPHeader)      + sizeof(RSVPSession) + sizeof(RSVPErrorSpec)
//                          + sizeof(RSVPResvConfirm) + sizeof(RSVPStyle)};
//    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
//    if (not packet)
//        return nullptr;
//
//    auto pos_ptr {packet->data()};
//    memset(pos_ptr, 0, size);
//
//    pos_ptr = RSVPHeader     ::write(pos_ptr, RSVPHeader::PathErr);
//    pos_ptr = RSVPSession    ::write(pos_ptr, 0x0f0f0f0f, 0x11, 4321);
//    pos_ptr = RSVPErrorSpec  ::write(pos_ptr, 0x76543210, 0x00);
//    pos_ptr = RSVPResvConfirm::write(pos_ptr, 0x0f0f0f0f);
//    pos_ptr = RSVPStyle      ::write(pos_ptr);
//
//    complete_header(packet, size);
//    return packet;
//}
//
//void RSVPSource::complete_header(WritablePacket* const packet, unsigned int const size) {
//
//    auto const header {(RSVPHeader*) packet->data()};
//    header->length = htons(size);
//    header->checksum = click_in_cksum(packet->data(), size);
//}

void RSVPSource::push(int, Packet*) {

//    switch (m_send) {
//    case 'P':
//        output(0).push((Packet*) generate_path());
//        break;
//    case 'R':
//        output(0).push((Packet*) generate_resv());
//        break;
//    case 'E':
//        output(0).push((Packet*) generate_path_err());
//        break;
//    case 'e':
//        output(0).push((Packet*) generate_resv_err());
//        break;
//    case 'T':
//        output(0).push((Packet*) generate_path_tear());
//        break;
//    case 't':
//        output(0).push((Packet*) generate_resv_tear());
//        break;
//    case 'C':
//        output(0).push((Packet*) generate_resv_conf());
//        break;
//    }
//    m_send = ' ';
}

Packet* RSVPSource::pull(int) {

//    switch (m_send) {
//    case 'P':
//        m_send = ' ';
//        return generate_path();
//    case 'R':
//        m_send = ' ';
//        return generate_resv();
//    case 'E':
//        m_send = ' ';
//        return generate_path_err();
//    case 'e':
//        m_send = ' ';
//        return generate_resv_err();
//    case 'T':
//        m_send = ' ';
//        return generate_path_tear();
//    case 't':
//        m_send = ' ';
//        return generate_resv_tear();
//    case 'C':
//        m_send = ' ';
//        return generate_resv_conf();
//    default:
//        m_send = ' ';
    return nullptr;
//    }
}

int RSVPSource::send(const String& config, Element* const element, void* const, ErrorHandler* const errh) {

    auto const source {(RSVPSource*) element};
    Vector<String> config_vector;
    cp_argvec(config, config_vector);
    String packet_type {""};

    if (Args(config_vector, source, errh)
            .read_mp("MSG", packet_type)
            .complete() < 0)
        return -1;

    if (packet_type == "Path")
        source->m_send = 'P';
    else if (packet_type == "Resv")
        source->m_send = 'R';
    else if (packet_type == "PathErr")
        source->m_send = 'E';
    else if (packet_type == "ResvErr")
        source->m_send = 'e';
    else if (packet_type == "PathTear")
        source->m_send = 'T';
    else if (packet_type == "ResvTear")
        source->m_send = 't';
    else if (packet_type == "ResvConf")
        source->m_send = 'C';
    else
        return -1;

    if (source->output_is_push(0))
        source->push(0, nullptr);
    return 0;
}

void RSVPSource::add_handlers() {

    add_write_handler("send", send, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPSource)
