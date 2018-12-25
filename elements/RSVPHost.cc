
#include <click/config.h>
#include "RSVPHost.hh"

#include <click/args.hh>
#include <click/glue.hh>

CLICK_DECLS

RSVPHost::RSVPHost() = default;

RSVPHost::~RSVPHost() = default;

int RSVPHost::configure(Vector<String>& config, ErrorHandler *const errh) {

    // Prepare variables for the parse results


    // Parse the config vector
    int result {Args(config, this, errh)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }
    return 0;
}

void RSVPHost::push(int, Packet*) {}

WritablePacket* RSVPHost::generate_path(const int session_id) {

    // Get the session with the given ID, make sure it exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet with the given size
    unsigned int const size {sizeof(RSVPHeader)     + sizeof(RSVPSession)        + sizeof(RSVPHop)
                           + sizeof(RSVPTimeValues) + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0 for safety
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    pos_ptr = RSVPHeader        ::write(pos_ptr, RSVPHeader::Path);
    pos_ptr = RSVPSession       ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    pos_ptr = RSVPHop           ::write(pos_ptr, session.source_address);
    pos_ptr = RSVPTimeValues    ::write(pos_ptr, s_refresh);
    pos_ptr = RSVPSenderTemplate::write(pos_ptr, session.source_address, session.source_port);
    pos_ptr = RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_max_unit, s_max_size);

    // Complete the RSVPHeader object by setting the size and checksum correctly
    complete_header(packet, size);
    return packet;
}

//WritablePacket* RSVPHost::generate_resv(const int session_id) {
//
//    unsigned int const size {sizeof(RSVPHeader)     + sizeof(RSVPSession) + sizeof(RSVPHop)
//                             + sizeof(RSVPTimeValues) + sizeof(RSVPStyle)};
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
//WritablePacket* RSVPHost::generate_path_err(const int session_id) {
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
//WritablePacket* RSVPHost::generate_resv_err(const int session_id) {
//
//    unsigned int const size{sizeof(RSVPHeader)    + sizeof(RSVPSession) + sizeof(RSVPHop)
//                            + sizeof(RSVPErrorSpec) + sizeof(RSVPStyle)};
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
//WritablePacket* RSVPHost::generate_path_tear(const int session_id) {
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
//WritablePacket* RSVPHost::generate_resv_tear(const int session_id) {
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
//WritablePacket* RSVPHost::generate_resv_conf(const int session_id) {
//
//    unsigned int const size{sizeof(RSVPHeader)      + sizeof(RSVPSession) + sizeof(RSVPErrorSpec)
//                            + sizeof(RSVPResvConfirm) + sizeof(RSVPStyle)};
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

void RSVPHost::complete_header(WritablePacket *const packet, const int size) {

    const auto header {(RSVPHeader*) packet->data()};
    header->length = htons(size);
    header->checksum = click_in_cksum(packet->data(), size);
}

int RSVPHost::session(const String& config, Element *const element, void *const thunk, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};
    in_addr destination_address {0};
    uint16_t destination_port {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_mp("DST", destination_address)
            .read_mp("PORT", destination_port)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID doesn't already exist
    if (host->m_sessions.find_pair(session_id)) {
        click_chatter("Session with ID %d already exists", session_id);
        return -1;
    }

    // Create a new session and add it to m_sessions
    Session session {destination_address, destination_port};
    host->m_sessions.insert(session_id, session);

    click_chatter("Registered session %d", session_id);
    return 0;
}

int RSVPHost::sender(const String& config, Element *const element, void *const thunk, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};
    in_addr source_address {0};
    uint16_t source_port {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_mp("SRC", source_address)
            .read_mp("PORT", source_port)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID does actually exist
    SessionMap::Pair *const pair {host->m_sessions.find_pair(session_id)};
    if (not pair) {
        click_chatter("Session with ID %d doesn't exist", session_id);
        return -1;
    }

    // Add the source address and port to the session
    pair->value.source_address = source_address;
    pair->value.source_port = source_port;

    // Start sending PATH messages
    host->output(0).push(host->generate_path(session_id));
    // TODO: set timer

    click_chatter("Defined session %d sender", session_id);
    return 0;
}

int RSVPHost::reserve(const String& config, Element *const element, void *const thunk, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};
    int confirmation {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_p("CONF", confirmation)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: confirm the reservation

    click_chatter("Reservation confirmed for session %d", session_id);
    return 0;
}

int RSVPHost::release(const String& config, Element *const element, void *const thunk, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: release session

    click_chatter("Released reservation for session %d", session_id);
    return 0;
}

void RSVPHost::add_handlers() {

    add_write_handler("session", session, 0);
    add_write_handler("sender", sender, 0);
    add_write_handler("reserve", reserve, 0);
    add_write_handler("release", release, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPHost)