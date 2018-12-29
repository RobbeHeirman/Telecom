
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

WritablePacket* RSVPHost::generate_path(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate PATH message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate PATH message; invalid sender ID received")) return nullptr;

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
    RSVPSession       ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop           ::write(pos_ptr, sender_id.source_address);
    RSVPTimeValues    ::write(pos_ptr, s_refresh);
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv(const SessionID& session_id, const FlowID& sender_id, const bool need_confirm) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate RESV message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.receivers.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate RESV message; invalid sender ID received")) return nullptr;

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
    RSVPSession   ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop       ::write(pos_ptr, sender_id.source_address);
    RSVPTimeValues::write(pos_ptr, s_refresh);
    if (need_confirm) {
        RSVPResvConfirm::write(pos_ptr, session_id.destination_address);
    }
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_path_err(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate PATH_ERR message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate PATH_ERR message; invalid sender ID received")) return nullptr;

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)         + sizeof(RSVPSession)     + sizeof(RSVPErrorSpec)
                           + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader        ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession       ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPErrorSpec     ::write(pos_ptr, session_id.destination_address, 0x00);
    // (destination address because this is a host and the source shouldn't send PATH_ERR messages)
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    // TODO copy template and tspec from PATH message

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_err(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate RESV_ERR message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate RESV_ERR message; invalid sender ID received")) return nullptr;

    // Create a new packet
    const unsigned int size{sizeof(RSVPHeader) + sizeof(RSVPSession)  + sizeof(RSVPHop)        + sizeof(RSVPErrorSpec)
                          + sizeof(RSVPStyle)  + sizeof(RSVPFlowSpec) + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader    ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession   ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop       ::write(pos_ptr, sender_id.source_address);
    RSVPErrorSpec ::write(pos_ptr, sender_id.source_address, 0x00);
    // (source address because this is a host and the destination shouldn't send RESV_ERR messages)
    RSVPStyle     ::write(pos_ptr);
    // TODO copy style from RESV message
    RSVPFlowSpec  ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_path_tear(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate PATH_TEAR message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate PATH_TEAR message; invalid sender ID received")) return nullptr;

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)         + sizeof(RSVPSession)     + sizeof(RSVPHop)
                           + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader        ::write(pos_ptr, RSVPHeader::PathTear);
    RSVPSession       ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop           ::write(pos_ptr, sender_id.source_address);
    // (source address because this is a host and the destination shouldn't send PATH_TEAR messages)
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_tear(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate RESV_TEAR message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate RESV_TEAR message; invalid sender ID received")) return nullptr;

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader) + sizeof(RSVPSession)    + sizeof(RSVPHop)
                           + sizeof(RSVPStyle)  + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader    ::write(pos_ptr, RSVPHeader::ResvTear);
    RSVPSession   ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop       ::write(pos_ptr, session_id.destination_address);
    // (destination address because this is a host and the source shouldn't send RESV_TEAR messages)
    RSVPStyle     ::write(pos_ptr);
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_conf(const SessionID& session_id, const FlowID& sender_id) {

    // Get the session and sender with the given IDs and make sure they are valid
    const auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "Couldn't generate RESV_CONF message; invalid session ID received")) return nullptr;

    const auto sender_pair {session_pair->value.senders.find_pair(sender_id.to_key())};
    if (check(not sender_pair, "Couldn't generate RESV_CONF message; invalid sender ID received")) return nullptr;

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)      + sizeof(RSVPSession)  + sizeof(RSVPErrorSpec)  + sizeof(RSVPStyle)
                           + sizeof(RSVPResvConfirm) + sizeof(RSVPFlowSpec) + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader     ::write(pos_ptr, RSVPHeader::PathErr);
    RSVPSession    ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPErrorSpec  ::write(pos_ptr, sender_id.source_address, 0x00);
    RSVPResvConfirm::write(pos_ptr, session_id.destination_address);
    // TODO copy resv confirm from RESV message
    RSVPStyle      ::write(pos_ptr);
    RSVPFlowSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec ::write(pos_ptr, sender_id.source_address, sender_id.source_port);

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
    if (check(not sender_template, "RSVPHost received PATH message without sender template object")) return;
    if (check(not sender_tspec, "RSVPHost received PATH message without sender TSpec object")) return;

    // Check whether the session's destination address and port matches any of the host's sessions
    const SessionID session_id {session->dest_addr, ntohs(session->dest_port), session->proto};
    auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "RSVPHost received PATH message that doesn't seem to belong here")) return;
    Session& local_session {session_pair->value};

    // Construct a flow ID and check whether this is the first PATH message received from that sender
    const FlowID sender_id {sender_template->src_addr, ntohs(sender_template->src_port)};
    auto sender_pair {local_session.receivers.find_pair(sender_id.to_key())};

    if (sender_pair) {
        // If this isn't the first PATH message, simply change the hop address if necessary
        if (sender_pair->value.hop_address != hop->address) {
            sender_pair->value.hop_address = hop->address; // TODO should this be checked instead of assigned?
        }
    } else {
        // If this is the first PATH message, create a new sender and add it with the sender ID
        const Flow receiver {hop->address, nullptr};
        local_session.receivers.insert(sender_id.to_key(), receiver);
    }

    // (Re-)set the lifetime timer of the session
    if (check(not local_session.lifetime, "RSVPHost has local session with invalid timer")) return;
    local_session.lifetime->reschedule_after_msec(6 * time_values->refresh);
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

    // Make sure the given session ID is valid
    const auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "PATH message can't be sent; invalid session ID received")) return;

    // Make sure the given sender ID is valid
    const auto sender_pair {session_pair->value.senders.find_pair(data->sender_id.to_key())};
    if (check(not sender_pair, "PATH message can't be sent; invalid sender ID received")) return;

    // Set the destination address and port in the IPEncap element
    data->host->set_ipencap(data->sender_id.source_address, data->session_id.destination_address);

    // Generate a new PATH message and push it
    const auto packet {data->host->generate_path(data->session_id, data->sender_id)};
    data->host->output(0).push(packet);

    // Set the timer again
    timer->reschedule_after_msec(s_refresh);
}

void RSVPHost::push_resv(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(ResvData*) user_data};
    if (check(not data, "RESV message can't be sent; no timer data received")) return;
    if (check(not data->host, "RESV message can't be sent; no host received")) return;

    // Make sure the given session ID is valid
    const auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "RESV message can't be sent; invalid session ID received")) return;
    const Session session {session_pair->value};

    // Make sure the given sender ID is valid
    const auto sender_pair {session.receivers.find_pair(data->sender_id.to_key())};
    if (check(not sender_pair, "RESV message can't be sent; invalid sender ID received")) return;

    // Provide the IPEncap element with the correct addresses
    data->host->set_ipencap(data->session_id.destination_address, sender_pair->value.hop_address);

    // Generate a new RESV message and push it
    const auto packet {data->host->generate_resv(data->session_id, data->sender_id, data->confirm)};
    data->host->output(0).push(packet);

    // Set the timer again
    timer->reschedule_after_msec(s_refresh);
}

void RSVPHost::release_session(Timer *const, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(ReleaseData*) user_data};
    if (check(not data, "Session can't be released; no timer data received")) return;
    if (check(not data->host, "Session can't be released; no host received")) return;

    auto pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not pair, "Session can't be released; invalid session ID received")) return;
    Session& session {pair->value};

    // Remove the session's senders and their timers
    for (auto iter {session.senders.begin()}; iter != session.senders.end(); ++iter) {
        delete iter.value().send;
    }
    session.senders.clear();

    // Remove the session itself and its lifetime timer
    delete pair->value.lifetime;
    data->host->m_sessions.erase(data->session_id.to_key());
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
    uint8_t proto {0x11};   // default: UDP (17)

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_mp("DST", destination_address)
            .read_mp("PORT", destination_port)
            .read("PROTO", proto)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID doesn't already exist
    if (host->m_session_ids.find_pair(session_id)) {
        return errh->warning("Session with ID %d already exists", session_id);
    }

    // Construct a new SessionID object and check whether one like it already exists
    const SessionID id {destination_address, destination_port, proto};
    if (host->m_sessions.find_pair(id.to_key())) {
        return errh->warning("Session with the same destination address and port already exists");
    }

    // Create a lifetime timer but don't schedule it yet
    auto data {new ReleaseData {host, id}};
    auto timer {new Timer {release_session, data}};
    timer->initialize(host);

    // Create a new session and add it to m_sessions
    Session session {FlowMap {}, FlowMap {}, timer};
    host->m_sessions.insert(id.to_key(), session);
    host->m_session_ids.insert(session_id, id);

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
    const auto pair {host->m_session_ids.find_pair(session_id)};
    if (not pair) {
        return errh->error("Session with ID %d doesn't exist", session_id);
    }
    Session& session {host->m_sessions.find_pair(pair->value.to_key())->value};

    // Create a new sender ID and check whether there already is one like it in the session's senders
    const FlowID sender_id {source_address, source_port};
    if (session.senders.find_pair(sender_id.to_key())) {
        return errh->warning("Sender with this source address and port already exists");
    }

    // Prepare the data for the new sender's timer
    const auto data {new PathData {host, pair->value, sender_id}};

    // Create a new sender object and add it to the session
    const Flow sender {0, new Timer {push_path, data}};
    session.senders.insert(sender_id.to_key(), sender);

    // Initialise the timer and schedule it immediately
    sender.send->initialize(host);
    sender.send->schedule_now();

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
    const auto pair {host->m_session_ids.find_pair(session_id)};
    if (not pair) {
        return errh->error("Session with ID %d doesn't exist", session_id);
    }
    Session& session {host->m_sessions.find_pair(pair->value.to_key())->value};

    // Check whether the session has already received a PATH message (there is a Flow object in the receivers map)
    if (session.receivers.empty()) {
        return errh->error("RSVPHost hasn't received any PATH messages for session %d yet", session_id);
    }

    // Start sending RESV messages to all senders that have already sent PATH messages
    for (auto iter {session.receivers.begin()}; iter != session.receivers.end(); ++iter) {
        Flow receiver {iter.value()};

        // Initialise a new timer if the receiver hasn't sent any RESV messages yet
        if (not receiver.send) {

            const auto data {new ResvData {host, pair->value, *(FlowID*)(&(iter.key())), confirmation}};
            receiver.send = new Timer {push_resv, data};
            receiver.send->initialize(host);
            // Start sending RESV messages immediately
            receiver.send->schedule_now();
        }
    }

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
    SessionIDMap::Pair *const pair {host->m_session_ids.find_pair(session_id)};
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