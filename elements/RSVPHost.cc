
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

    // Make sure the header is valid
    if (check(header->version != RSVPVersion, "RSVPHost received packet with invalid version")) return;
    if (check(click_in_cksum(packet->data(), ntohs(header->length)) != 0,
            "RSVPHost received packet with invalid checksum")) return;

    // React based on the message type in the header
    switch (header->msg_type) {
        case RSVPHeader::Path:
            return parse_path(packet);
        case RSVPHeader::Resv:
            return parse_resv(packet);
        case RSVPHeader::PathErr:
            return parse_path_err(packet);
        case RSVPHeader::ResvErr:
            return parse_resv_err(packet);
        case RSVPHeader::PathTear:
            return parse_path_tear(packet);
        case RSVPHeader::ResvTear:
            return parse_resv_err(packet);
        case RSVPHeader::ResvConf:
            return parse_resv_conf(packet);
        default:
            ErrorHandler::default_handler()->error("RSVPHost received packet with an invalid message type");
    }
}

WritablePacket* RSVPHost::generate_path(const SessionID& session_id, const SenderID& sender_id) {

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

WritablePacket* RSVPHost::generate_resv(const SessionID& session_id, const SenderID& sender_id, const bool need_confirm) {

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

WritablePacket* RSVPHost::generate_resv_conf(const SessionID& session_id, const SenderID& sender_id) {

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

void RSVPHost::parse_path(const Packet *const packet) {

    // Find all the objects we need from the message
    Path path {};
    if (check(not find_path_ptrs(packet, path), "RSVPHost received an ill-formed PATH message")) return;

    // Check whether the session's destination address and port matches any of the host's sessions
    const SessionID session_id {path.session->dest_addr, ntohs(path.session->dest_port), path.session->proto};
    auto session_pair {m_sessions.find_pair(session_id.to_key())};
    if (check(not session_pair, "RSVPHost received PATH message that doesn't seem to belong here")) return;
    Session& local_session {session_pair->value};

    // Construct a flow ID and check whether this is the first PATH message received from that sender
    const SenderID sender_id {path.sender.sender->src_addr, ntohs(path.sender.sender->src_port)};
    auto sender_pair {local_session.receivers.find_pair(sender_id.to_key())};
    State* state;

    if (sender_pair) {
        // If this isn't the first PATH message, simply change the hop address if necessary
        state = &(sender_pair->value);
        if (state->hop_address != path.hop->address) {
            state->hop_address = path.hop->address; // TODO should this be checked instead of assigned?
        }
    } else {
        // If this is the first PATH message, start with creating a new lifetime timer
        const auto timer {new Timer {tear_state, new TearData {this, session_id, sender_id, false}}};
        timer->initialize(this);

        // Create a new state and add it to the receiver map
        State receiver {path.hop->address, nullptr, timer};
        local_session.receivers.insert(sender_id.to_key(), receiver);
        state = &receiver;
    }

    // (Re-)set the lifetime timer of the state
    if (check(not state->lifetime, "RSVPHost has local session with invalid timer")) return;
    state->lifetime->reschedule_after_msec(6 * path.time_values->refresh);
}

void RSVPHost::parse_resv(const Packet *const ) {


}

void RSVPHost::parse_path_err(const Packet *const ) {

    // TODO
}

void RSVPHost::parse_resv_err(const Packet *const ) {

    // TODO
}

void RSVPHost::parse_path_tear(const Packet *const ) {

    // TODO
}

void RSVPHost::parse_resv_tear(const Packet *const ) {

    // TODO
}

void RSVPHost::parse_resv_conf(const Packet *const ) {

    // TODO
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

void RSVPHost::tear_state(Timer *const, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(TearData*) user_data};
    if (check(not data, "State can't be released; no timer data received")) return;
    if (check(not data->host, "State can't be released; no host received")) return;

    auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "State can't be released; invalid session ID received")) return;
    Session& session {session_pair->value};

    // Find the state in the senders/receivers map depending on whether the host was the sender/receiver
    if (data->sender) {
        auto state_pair {session.senders.find_pair(data->sender_id.to_key())};
        if (check(not state_pair, "State can't be released; invalid sender ID received")) return;
        session.senders.erase(data->sender_id.to_key());

        // TODO send PATH_TEAR message

    } else {
        auto state_pair {session.receivers.find_pair(data->sender_id.to_key())};
        if (check(not state_pair, "State can't be released; invalid sender ID received")) return;
        session.receivers.erase(data->sender_id.to_key());

        // TODO send RESV_TEAR message
    }
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

    // Create a new session and add it to m_sessions
    Session session {StateMap {}, StateMap {}};
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
    const SenderID sender_id {source_address, source_port};
    if (session.senders.find_pair(sender_id.to_key())) {
        return errh->warning("Sender with this source address and port already exists");
    }

    // Prepare the data for the new sender's timers
    const auto path_data {new PathData {host, pair->value, sender_id}};
    const auto tear_data {new TearData {host, pair->value, sender_id, true}};

    // Create a new sender object and add it to the session
    const State sender {0, new Timer {push_path, path_data}, new Timer {tear_state, tear_data}};
    session.senders.insert(sender_id.to_key(), sender);

    // Initialise and schedule the timers
    sender.send->initialize(host);
    sender.send->schedule_now();
    sender.lifetime->initialize(host);
    sender.lifetime->schedule_after_msec(6 * s_refresh);

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
    int id {0};
    bool confirmation {true};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", id)
            .read_p("CONF", confirmation)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID does actually exist
    const auto pair {host->m_session_ids.find_pair(id)};
    if (not pair) {
        return errh->error("Session with ID %d doesn't exist", id);
    }
    const auto session_id {pair->value};
    Session& session {host->m_sessions.find_pair(session_id.to_key())->value};

    // Check whether the session has already received a PATH message (there is a State object in the receivers map)
    if (session.receivers.empty()) {
        return errh->error("RSVPHost hasn't received any PATH messages for session %d yet", id);
    }

    // Start sending RESV messages to all senders that have already sent PATH messages
    for (auto iter {session.receivers.begin()}; iter != session.receivers.end(); ++iter) {
        State receiver {iter.value()};

        // Initialise a new timer if the receiver hasn't sent any RESV messages yet
        if (not receiver.send) {
            const auto resv_data {new ResvData {host, session_id, SenderID::from_key(iter.key()), confirmation}};
            receiver.send = new Timer {push_resv, resv_data};
            receiver.send->initialize(host);
            receiver.send->schedule_now();
        };
    }

    errh->message("Reservation confirmed for session %d", id);
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