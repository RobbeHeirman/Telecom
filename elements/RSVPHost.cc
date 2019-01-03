
#include <click/config.h>
#include "RSVPHost.hh"

#include <arpa/inet.h>
#include <click/args.hh>
#include <click/glue.hh>

CLICK_DECLS


RSVPHost::RSVPHost() = default;

RSVPHost::~RSVPHost() = default;

int RSVPHost::configure(Vector<String>& , ErrorHandler *const ) {

//    // Parse the config vector
//    int result {Args(config, this, errh)
//            .complete()};
//
//    // Check whether the parse failed
//    if (result < 0) {
//        return -1;
//    }
    return 0;
}

void RSVPHost::push(int, Packet *const packet) {

    // Get the header from the RSVP message
    const auto header {(RSVPHeader*) (packet->data() + packet->ip_header_length())};

    // Make sure the header is valid
    if (check(header->version != RSVPVersion, "RSVPHost received packet with invalid version")) return;
    if (check(click_in_cksum((unsigned char*) header, ntohs(header->length)),
            "RSVPHost received packet with invalid checksum")) return;

    // React based on the message type in the header
    switch (header->msg_type) {
        case RSVPHeader::Path:
            return parse_path((unsigned char*) header);
        case RSVPHeader::Resv:
            return parse_resv((unsigned char*) header);
        case RSVPHeader::PathErr:
            return parse_path_err((unsigned char*) header);
        case RSVPHeader::ResvErr:
            return parse_resv_err((unsigned char*) header);
        case RSVPHeader::PathTear:
            return parse_path_tear((unsigned char*) header);
        case RSVPHeader::ResvTear:
            return parse_resv_tear((unsigned char*) header);
        case RSVPHeader::ResvConf:
            return parse_resv_conf((unsigned char*) header);
        default:
            ErrorHandler::default_handler()->error("RSVPHost received packet with an invalid message type");
    }

    packet->kill();
}

WritablePacket* RSVPHost::generate_path(const SessionID& session_id, const SenderID& sender_id) {

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
    RSVPTimeValues    ::write(pos_ptr, R);
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv(const SessionID& session_id, const SenderID& sender_id, const bool confirm) {

    // Create a new packet
    const unsigned long size {sizeof(RSVPHeader)     + sizeof(RSVPSession)                    + sizeof(RSVPHop)
                            + sizeof(RSVPTimeValues) + (confirm? sizeof(RSVPResvConfirm) : 0) + sizeof(RSVPStyle)
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
    RSVPTimeValues::write(pos_ptr, R);
    if (confirm) {
        RSVPResvConfirm::write(pos_ptr, session_id.destination_address);
    }
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPHost::generate_resv_conf(const SessionID& session_id, const SenderID& sender_id, const Resv& resv) {

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
    RSVPHeader     ::write(pos_ptr, RSVPHeader::ResvConf);
    RSVPSession    ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPErrorSpec  ::write(pos_ptr, sender_id.source_address, 0x00);

    // The ResvConf object should be copied from a RESV message
    RSVPResvConfirm& resv_confirm = *(RSVPResvConfirm*) pos_ptr;
    resv_confirm = *(resv.resv_confirm);
    pos_ptr = (unsigned char*)((RSVPResvConfirm*)(pos_ptr) + 1);

    RSVPStyle      ::write(pos_ptr);
    RSVPFlowSpec   ::write(pos_ptr, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);
    RSVPFilterSpec ::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader     ::complete(packet, size);
    return packet;
}

void RSVPHost::parse_path(const unsigned char *const packet) {

    // Get all the objects we need from the message
    Path path {};
    if (check(not find_path_ptrs(packet, path), "RSVPHost received an ill-formed PATH message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*path.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received PATH message that doesn't seem to belong here")) return;
    SessionStates& session {session_pair->value};

    // Construct a SenderID object and check whether this is the first PATH message received from that sender
    const uint64_t sender_key {SenderID::to_key(*path.sender.sender)};
    auto sender_pair {session.receivers.find_pair(sender_key)};

    // If this is the first PATH message; create, initialise and add a new state
    if (not sender_pair) {
        // Create the new state first and get the session and sender IDs with which it will be added
        PathState receiver;
        const SessionID session_id {SessionID::from_key(session_key)};
        const SenderID sender_id {SenderID::from_key(sender_key)};

        // Create new timers and initialise them (scheduling happens at the end of the function or in a handler)
        receiver.tear_data = new TearData {this, session_id, sender_id, false};
        receiver.timeout_timer = new Timer {tear_state, receiver.tear_data};
        receiver.timeout_timer->initialize(this);
        receiver.refresh_timer = nullptr;
        // If the send timer is still zero push_resv knows there it hasn't sent a RESV message yet

        // Collect the PATH message's PolicyData and SenderTSpec objects and add them to the state
        receiver.policy_data = Vector<RSVPPolicyData> {};
        for (auto iter {path.policy_data.begin()}; iter < path.policy_data.end(); ++iter) {
            receiver.policy_data.push_back(**iter);     // iter is a pointer to a pointer
        }
        receiver.t_spec = *(path.sender.tspec);

        // And add the new state
        session.receivers.insert(sender_key, receiver);
    }

    // (Re-)set the timeout timer of the state and set the prev_hop address
    auto state = session.receivers.findp(sender_key);
    if (check(not state->timeout_timer, "RSVPHost has local session with invalid timer")) return;
    state->timeout_timer->reschedule_after_msec(6 * path.time_values->refresh);
    state->prev_hop = path.hop->address;
}

void RSVPHost::parse_resv(const unsigned char *const packet) {

    // Get all the objects we need from the message
    Resv resv {};
    if (check(not find_resv_ptrs(packet, resv), "RSVPHost received an ill-formed RESV message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*resv.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received RESV message that doesn't seem to belong here")) return;
    SessionStates& session {session_pair->value};

    // Check whether there are senders registered for the session that match the RESV message's flow descriptors
    for (auto flow {resv.flow_descriptor_list.begin()}; flow < resv.flow_descriptor_list.end(); ++flow) {
        const uint64_t sender_key {SenderID::to_key(*flow->filter_spec)};

        auto sender_pair {session.senders.find_pair(sender_key)};
        if (check(not sender_pair,
                "RSVPHost received RESV message with a flow descriptor that doesn't match any sender")) return;
        PathState& state {sender_pair->value};

        // Set the hop address of this state
        state.prev_hop = resv.hop->address;

        // Check whether a RESV_CONF message is requested, if so generate and send it
        if (resv.resv_confirm) {
            auto packet {generate_resv_conf(SessionID::from_key(session_key), SenderID::from_key(sender_key), resv)};
            ipencap(packet, resv.session->dest_addr, flow->filter_spec->src_addr);
            output(0).push(packet);
        }
    };
}

void RSVPHost::parse_path_err(const unsigned char *const ) {

    // TODO
}

void RSVPHost::parse_resv_err(const unsigned char *const ) {

    // TODO
}

void RSVPHost::parse_path_tear(const unsigned char *const packet) {

    // Get all the objects we need from the packet
    PathTear path_tear {};
    if (check(not find_path_tear_ptrs(packet, path_tear), "RSVPHost received an ill-formed PATH_TEAR message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*path_tear.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received PATH_TEAR message that doesn't seem to belong here")) return;
    SessionStates& session {session_pair->value};

    // Check whether there is a receiver registered that matches the PATH_TEAR message's SenderTemplate object
    const uint64_t sender_key {SenderID::to_key(*path_tear.sender_template)};
    auto sender_pair {session.receivers.find_pair(sender_key)};
    if (check(not session_pair,
            "RSVPHost received PATH_TEAR message from a sender that is not registered to the session")) return;
    PathState& state {sender_pair->value};

    // Reschedule the state's timeout timer to immediately trigger
    state.timeout_timer->schedule_now();
};

void RSVPHost::parse_resv_tear(const unsigned char *const ) {

    // TODO
}

void RSVPHost::parse_resv_conf(const unsigned char *const ) {

    // TODO
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
    SessionStates session {StateMap {}, StateMap {}};
    host->m_sessions.insert(id.to_key(), session);
    host->m_session_ids.insert(session_id, id.to_key());

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
    int id {0};
    in_addr source_address {0};
    uint16_t source_port {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", id)
            .read_mp("SRC", source_address)
            .read_mp("PORT", source_port)
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
    const SessionID session_id {SessionID::from_key(pair->value)};
    SessionStates& session {host->m_sessions.find_pair(pair->value)->value};

    // Create a new sender ID and check whether there already is one like it in the session's senders
    const SenderID sender_id {source_address, source_port};
    if (session.senders.find_pair(sender_id.to_key())) {
        return errh->warning("Sender with this source address and port already exists");
    }

    // Create a new sender object
    PathState sender;
    sender.policy_data = Vector<RSVPPolicyData> {};

    // Prepare the data for the new sender's timers
    sender.send_data = (void*) new PathData {host, session_id, sender_id};
    sender.tear_data = new TearData {host, session_id, sender_id, true};

    // Create, initialise and add new timers for/to the sender
    sender.refresh_timer = new Timer {push_path, sender.send_data};
    sender.refresh_timer->initialize(host);
    sender.refresh_timer->schedule_now();
    sender.timeout_timer = new Timer {tear_state, sender.tear_data};
    sender.timeout_timer->initialize(host);
    sender.timeout_timer->schedule_after_msec((K + 0.5) * 1.5 * R);

    // Create a new SenderTSpec object and add it as well
    sender.t_spec = RSVPSenderTSpec {};
    auto temp {(unsigned char*) &(sender.t_spec)};
    RSVPSenderTSpec::write(temp, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

    // Once initialised add the sender to the session and immediately send a PATH message
    session.senders.insert(sender_id.to_key(), sender);

    errh->message("Defined session %d sender %u", id, sender_id.to_key());
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
    SessionStates& session {host->m_sessions.find_pair(session_id)->value};

    // Check whether the session has already received a PATH message (there is a State object in the receivers map)
    if (session.receivers.empty()) {
        return errh->error("RSVPHost hasn't received any PATH messages for session %d yet", id);
    }

    // Start sending RESV messages to all senders that have already sent PATH messages
    for (auto iter {session.receivers.begin()}; iter != session.receivers.end(); ++iter) {
        PathState receiver {iter.value()};

        // Initialise a new timer if the receiver hasn't sent any RESV messages yet
        if (not receiver.refresh_timer) {
            receiver.send_data = (void*) new ResvData {host, SessionID::from_key(session_id),
                                                       SenderID::from_key(iter.key()), confirmation};
            receiver.refresh_timer = new Timer {push_resv, receiver.send_data};
            receiver.refresh_timer->initialize(host);
            receiver.refresh_timer->schedule_after_msec(R);
            push_resv(receiver.refresh_timer, receiver.send_data);
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

    // Generate a new PATH message and push it
    const auto packet {data->host->generate_path(data->session_id, data->sender_id)};
    data->host->ipencap(packet, data->sender_id.source_address, data->session_id.destination_address);
    data->host->output(0).push(packet);

    // Set the timer again
    timer->reschedule_after_msec(R);
}

void RSVPHost::push_resv(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(ResvData*) user_data};
    if (check(not data, "RESV message can't be sent; no timer data received")) return;
    if (check(not data->host, "RESV message can't be sent; no host received")) return;

    // Make sure the given session ID is valid
    const auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "RESV message can't be sent; invalid session ID received")) return;
    const SessionStates session {session_pair->value};

    // Make sure the given sender ID is valid
    const auto sender_pair {session.receivers.find_pair(data->sender_id.to_key())};
    if (check(not sender_pair, "RESV message can't be sent; invalid sender ID received")) return;

    // Generate a new RESV message and push it
    const auto packet {data->host->generate_resv(data->session_id, data->sender_id, data->confirm)};
    data->host->ipencap(packet, data->session_id.destination_address, sender_pair->value.prev_hop);
    data->host->output(0).push(packet);

    // Set the timer again and make sure only the first message contains a ResvConf object
    timer->reschedule_after_msec(R);
    data->confirm = false;
}

void RSVPHost::tear_state(Timer *const, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(TearData*) user_data};
    if (check(not data, "State can't be released; no timer data received")) return;
    if (check(not data->host, "State can't be released; no host received")) return;

    auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "State can't be released; invalid session ID received")) return;
    SessionStates& session {session_pair->value};

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


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPHost)