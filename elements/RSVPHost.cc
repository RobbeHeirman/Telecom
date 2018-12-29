
#include <click/config.h>
#include "RSVPHost.hh"

#include <arpa/inet.h>
#include <click/args.hh>
#include <click/glue.hh>

CLICK_DECLS

RSVPHost::RSVPHost() = default;

RSVPHost::~RSVPHost() = default;

int RSVPHost::configure(Vector<String>& config, ErrorHandler *const errh) {

    // Parse the config vector
    int result {Args(config, this, errh)
            .read_mp("IPENCAP", ElementCastArg("IPEncap"), m_ipencap)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        m_ipencap = nullptr;
        return -1;
    }
    return 0;
}

void RSVPHost::push(int, Packet *const packet) {

    // Extract the RSVP header
    RSVPHeader *const header {(RSVPHeader*) packet->data()};

    // Get the location and length of all RSVP objects combined (no header)
    const unsigned char *const data {packet->data() + sizeof(header)};
    const auto size {(uint16_t) (ntohs(header->length) - sizeof(header))};

    // Make sure the header is valid
    if (check(header->version != RSVPVersion, "RSVPHost received packet with invalid version")) return;
    if (check(click_in_cksum(packet->data(), ntohs(header->length)) != 0,
            "RSVPHost received packet with invalid checksum")) return;

    // React based on the message type in the header
    switch (header->msg_type) {
        case RSVPHeader::Path:
            return parse_path(data, size);
        case RSVPHeader::Resv:
            return parse_resv(data, size);
        case RSVPHeader::PathErr:
            return parse_path_err(data, size);
        case RSVPHeader::ResvErr:
            return parse_resv_err(data, size);
        case RSVPHeader::PathTear:
            return parse_path_tear(data, size);
        case RSVPHeader::ResvTear:
            return parse_resv_err(data, size);
        case RSVPHeader::ResvConf:
            return parse_resv_conf(data, size);
        default:
            ErrorHandler::default_handler()->error("RSVPHost received packet with an invalid message type");
    }
}

WritablePacket* RSVPHost::generate_path(const int session_id) {

    // Get the session with the given ID, make sure it exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)     + sizeof(RSVPSession)        + sizeof(RSVPHop)
                           + sizeof(RSVPTimeValues) + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader        ::write(pos_ptr, RSVPHeader::Path);
    RSVPSession       ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPHop           ::write(pos_ptr, session.source_address);
    RSVPTimeValues    ::write(pos_ptr, s_refresh);
    RSVPSenderTemplate::write(pos_ptr, session.source_address, session.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv(const int session_id, const bool need_confirm) {

    // Get the session with the given ID, make sure it exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned long size {sizeof(RSVPHeader)     + sizeof(RSVPSession)                         + sizeof(RSVPHop)
                            + sizeof(RSVPTimeValues) + (need_confirm? sizeof(RSVPResvConfirm) : 0) + sizeof(RSVPStyle)
                            + sizeof(RSVPFlowSpec)   + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader    ::write(pos_ptr, RSVPHeader::Resv);
    RSVPSession   ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPHop       ::write(pos_ptr, session.source_address);
    RSVPTimeValues::write(pos_ptr, s_refresh);
    if (need_confirm) {
        RSVPResvConfirm::write(pos_ptr, session.destination_address);
    }
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec::write(pos_ptr, session.source_address, session.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_path_err(const int session_id) {

    // Get the session with the given ID, make sure it exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPErrorSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader   ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession  ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPErrorSpec::write(pos_ptr, session.destination_address, 0x00);
    // (destination address because this is a host and the source shouldn't send PATH_ERR messages)

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_err(const int session_id) {

    // Get the session with the given ID, make sure it exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size{sizeof(RSVPHeader)    + sizeof(RSVPSession) + sizeof(RSVPHop)
                          + sizeof(RSVPErrorSpec) + sizeof(RSVPStyle)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader   ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession  ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPHop      ::write(pos_ptr, session.source_address);
    RSVPErrorSpec::write(pos_ptr, session.source_address, 0x00);
    // (source address because this is a host and the destination shouldn't send RESV_ERR messages)
    RSVPStyle    ::write(pos_ptr);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_path_tear(const int session_id) {

    // Get the session with the given ID, make sure it actually exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPHop)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader ::write(pos_ptr, RSVPHeader::PathTear);
    RSVPSession::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPHop    ::write(pos_ptr, session.source_address);
    // (source address because this is a host and the destination shouldn't send PATH_TEAR messages)

    // Complete the header by setting the size and checksum correctly
    RSVPHeader ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_tear(const int session_id) {

    // Get the session with the given ID, make sure it actually exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader) + sizeof(RSVPSession) + sizeof(RSVPHop) + sizeof(RSVPStyle)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader ::write(pos_ptr, RSVPHeader::ResvTear);
    RSVPSession::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPHop    ::write(pos_ptr, session.destination_address);
    // (destination address because this is a host and the source shouldn't send RESV_TEAR messages)
    RSVPStyle  ::write(pos_ptr);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_conf(const int session_id) {

    // Get the session with the given ID, make sure it actually exists
    SessionMap::Pair *const pair {m_sessions.find_pair(session_id)};
    assert(pair);
    const Session session {pair->value};

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)      + sizeof(RSVPSession) + sizeof(RSVPErrorSpec)
                           + sizeof(RSVPResvConfirm) + sizeof(RSVPStyle)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader     ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession    ::write(pos_ptr, session.destination_address, 0x11, session.destination_port);
    RSVPErrorSpec  ::write(pos_ptr, session.source_address, 0x00);
    RSVPResvConfirm::write(pos_ptr, session.destination_address);
    RSVPStyle      ::write(pos_ptr);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader     ::complete(packet, size);
    return packet;
}

void RSVPHost::parse_path(const unsigned char *const message, const int size) {

    // A variable to keep track of how much of the message has been processed
    int processed {0};

    // Check whether there is an integrity object (should be directly after the header), if so skip it
    const auto poss_integrity {(RSVPObject*) message};
    if (poss_integrity->class_num == RSVPObject::Integrity) {
        processed = sizeof(RSVPIntegrity);
    }

    // Some variables to hold the results of the parse
    RSVPSession* session {nullptr};
    RSVPHop* hop {nullptr};
    RSVPTimeValues* time_values {nullptr};
    RSVPSenderTemplate* sender_template {nullptr};
    RSVPSenderTSpec* sender_tspec {nullptr};

    // Loop over the packet until all objects have been processed
    while (processed < size) {

        // Extract the common object header and its class number
        auto *const object {(RSVPObject*) (message + processed)};
        switch (object->class_num) {

            case RSVPObject::Session:
                // Make sure this is the first session object found
                if (check(session, "RSVPHost received PATH message with multiple session objects")) return;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                // Make sure this is the first hop object found
                if (check(hop, "RSVPHost received PATH message with multiple hop objects")) return;
                hop = (RSVPHop*) object;
                break;

            case RSVPObject::TimeValues:
                // Make sure this is the first time values object found
                if (check(time_values, "RSVPHost received PATH message with multiple time values objects")) return;
                time_values = (RSVPTimeValues*) object;
                break;

            case RSVPObject::SenderTemplate:
                // Make sure this is the first sender template object found
                if (check(sender_template,
                        "RSVPHost received PATH message with multiple sender template objects")) return;
                sender_template = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                // Make sure this is the first sender tspec object found
                if (check(sender_tspec, "RSVPHost received PATH message with multiple sender tspec objects")) return;
                sender_tspec = (RSVPSenderTSpec*) object;
                break;

            case RSVPObject::PolicyData:
                // Skip any policy data objects
                break;

            default:
                // Any other objects shouldn't be in a PATH message
                check(true, "RSVPHost received PATH message with an object with an invalid class number");
                return;
        }
        processed += ntohs(object->length);
    }

    // Make sure the mandatory objects are present in the message
    if (check(not session, "RSVPHost received PATH message without session object")) return;
    if (check(not hop, "RSVPHost received PATH message without hop object")) return;
    if (check(not time_values, "RSVPHost received PATH message without time values object")) return;

    // Check whether the session's destination address and port matches any of the host's sessions
    Session* local_session {nullptr};
    for (auto session_iter {m_sessions.begin()}; session_iter != m_sessions.end(); ++session_iter) {
        Session& current {session_iter.value()};

        // Match destination address and port assuming protocol is UDP
        if (current.destination_address == session->dest_addr
                and current.destination_port == ntohs(session->dest_port)) {
            local_session = &current;
            break;
        }
    }
    // Make sure a session was found
    if (not local_session) return;

    // Check whether this is the first PATH message received for this session based on the source address
    if (local_session->source_address == 0) {

        // Make sure there is a sender template object in the message, and set the source address and port
        if (check(not sender_template, "RSVPHost received (first) PATH message without sender template object")) return;
        local_session->source_address = sender_template->src_addr;
        local_session->source_port = ntohs(sender_template->src_port);

        local_session->hop_address = hop->address;
    } else {

        // Make sure the hop address is correct and if possible check the source address and port as well
        if (check(local_session->hop_address != hop->address,
                "RSVPHost received PATH message with different hop address than the initial address")) return;
        if (sender_template) {
            if (check(local_session->source_address != sender_template->src_addr,
                    "RSVPHost received PATH message with different source address than the initial address")) return;
            if (check(local_session->source_port != ntohs(sender_template->src_port),
                    "RSVPHost received PATH message with different source port than the initial port")) return;
        }
    }

    // (Re-)set the lifetime timer of the session
    if (check(not local_session->lifetime, "RSVPHost has local session with invalid timer")) return;
    local_session->lifetime->reschedule_after_msec(6 * time_values->refresh);
}

void RSVPHost::parse_resv(const unsigned char *const , const int ) {

    // TODO
}

void RSVPHost::parse_path_err(const unsigned char *const , const int ) {

    // TODO
}

void RSVPHost::parse_resv_err(const unsigned char *const , const int ) {

    // TODO
}

void RSVPHost::parse_path_tear(const unsigned char *const , const int ) {

    // TODO
}

void RSVPHost::parse_resv_tear(const unsigned char *const , const int ) {

    // TODO
}

void RSVPHost::parse_resv_conf(const unsigned char *const , const int ) {

    // TODO
}

bool RSVPHost::check(const bool condition, const String& message) {

    if (condition) {
        ErrorHandler::default_handler()->error(message.c_str());
    }
    return condition;
}

void RSVPHost::push_path(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(PathData*) user_data};
    if (check(not data, "PATH message can't be sent; no timer data received")) return;
    if (check(not data->host, "PATH message can't be sent; no host received")) return;

    // Get the session with the given ID
    const auto *const pair {data->host->m_sessions.find_pair(data->session_id)};
    if (check(not pair, "PATH message can't be sent; invalid session ID")) return;
    const Session session {pair->value};

    // Set the destination address and port in the IPEncap element
    data->host->set_ipencap(session.source_address, session.destination_address);

    // Generate a new PATH message and push it
    const auto packet {data->host->generate_path(data->session_id)};
    data->host->output(0).push(packet);

    // Set the timer again
    timer->reschedule_after_msec(s_refresh);
}

void RSVPHost::push_resv(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(ResvData*) user_data};
    if (check(not data, "RESV message can't be sent; no timer data received")) return;
    if (check(not data->host, "RESV message can't be sent; no host received")) return;

    // Get the session with the given ID
    auto *const pair {data->host->m_sessions.find_pair(data->session_id)};
    if (check(not pair, "RESV message can't be sent; invalid session ID")) return;
    const Session session {pair->value};

    // Set the destination address and port in the configuration
    data->host->set_ipencap(session.destination_address, session.hop_address);

    // Generate a new RESV message and push it
    const auto packet {data->host->generate_resv(data->session_id, data->confirm)};
    data->host->output(0).push(packet);

    // Set the timer again
    timer->reschedule_after_msec(s_refresh);
}

void RSVPHost::release_session(Timer *const, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(ReleaseData*) user_data};
    if (check(not data, "Session can't be released; no timer data received")) return;
    if (check(not data->host, "Session can't be released; no host received")) return;
    auto* pair {data->host->m_sessions.find_pair(data->session_id)};
    if (check(not pair, "Session can't be released; invalid session ID received")) return;

    // Remove the session from the host
    delete pair->value.send;
    delete pair->value.lifetime;
    data->host->m_sessions.erase(data->session_id);
};

void RSVPHost::set_ipencap(const in_addr& source, const in_addr& destination) {

    // Make sure m_ipencap actually exists
    assert(m_ipencap);

    // Prepare a buffer and a vector to hold the configuration and result (resp.)
    char buf[INET_ADDRSTRLEN] {};
    Vector<String> config {};

    // Convert and add the source and destination address to the configuration; make sure the protocol is set to RSVP
    config.push_back(String("46"));                                                     // PROTO (46 = RSVP)
    config.push_back(String(inet_ntop(AF_INET, &source, buf, INET_ADDRSTRLEN)));        // SRC
    config.push_back(String(inet_ntop(AF_INET, &destination, buf, INET_ADDRSTRLEN)));   // DST

    // Configure the IPEncap element with the configuration
    m_ipencap->live_reconfigure(config, ErrorHandler::default_handler());
}

int RSVPHost::session(const String& config, Element *const element, void *const, ErrorHandler *const errh) {

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
        return errh->warning("Session with ID %d already exists", session_id);
    }

    // Create a lifetime timer but don't schedule it yet
    auto data {new ReleaseData {host, session_id}};
    auto timer {new Timer {release_session, data}};
    timer->initialize(host);

    // Create a new session and add it to m_sessions
    Session session {destination_address, destination_port, 0, 0, 0, nullptr, timer};
    host->m_sessions.insert(session_id, session);

    errh->message("Registered session %d", session_id);
    return 0;
}

int RSVPHost::sender(const String& config, Element *const element, void *const, ErrorHandler *const errh) {

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
        return errh->error("Session with ID %d doesn't exist", session_id);
    }
    Session& session {pair->value};

    // Add the source address and port to the session
    session.source_address = source_address;
    session.source_port = source_port;

    // Start sending PATH messages
    PathData *const data {new PathData {host, session_id}};
    session.send = new Timer {push_path, data};
    session.send->initialize(host);
    session.send->schedule_now();

    errh->message("Defined session %d sender", session_id);
    return 0;
}

int RSVPHost::reserve(const String& config, Element *const element, void *const, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};
    bool confirmation {true};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_p("CONF", confirmation)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID does actually exist
    SessionMap::Pair *const pair {host->m_sessions.find_pair(session_id)};
    if (not pair) {
        return errh->error("Session with ID %d doesn't exist", session_id);
    }
    Session& session {pair->value};

    // Check whether the session has already received a PATH message (source address isn't 0 anymore)
    if (session.source_address == 0) {
        return errh->error("RSVPHost hasn't received any PATH messages for session %d yet", session_id);
    }

    // Start sending RESV messages
    ResvData *const data {new ResvData {host, session_id, confirmation}};
    session.send = new Timer {push_resv, data};
    session.send->initialize(host);
    session.send->schedule_now();

    errh->message("Reservation confirmed for session %d", session_id);
    return 0;
}

int RSVPHost::release(const String& config, Element *const element, void *const, ErrorHandler *const errh) {

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

    // Check whether a session with the give ID does actually exist
    SessionMap::Pair *const pair {host->m_sessions.find_pair(session_id)};
    if (not pair) {
        return errh->error("Session with ID %d doesn't exist", session_id);
    }

    // TODO: release session

    errh->message("Released reservation for session %d", session_id);
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