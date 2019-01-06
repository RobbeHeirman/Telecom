
#include <click/config.h>
#include "RSVPHost.hh"

#include <arpa/inet.h>
#include <click/args.hh>
#include <click/glue.hh>
#include <click/straccum.hh>

CLICK_DECLS


RSVPHost::RSVPHost() = default;

RSVPHost::~RSVPHost() = default;

int RSVPHost::configure(Vector<String>& config, ErrorHandler *const errh) {

    // Parse the config vector and check whether it succeeded
    if (Args(config, this, errh)
            .read_mp("IP", m_address_info)
            .complete() < 0) {
        return -1;
    }
    return 0;
}

void RSVPHost::push(int, Packet *const packet) {

    // Get the header from the RSVP message
    const auto ip_header = (click_ip*) packet->data();
    const auto header {(RSVPHeader*) (packet->data() + 4 * ip_header->ip_hl)};

    // Make sure the packet is a valid RSVP message with an IP header
    if (check(not validate_message(packet), "RSVPHost received an ill-formed RSVP message")) return;

    // React based on the message type in the header
    switch (header->msg_type) {
        case RSVPHeader::Path:
            return handle_path((unsigned char*) header);
        case RSVPHeader::Resv:
            return handle_resv((unsigned char*) header);
        case RSVPHeader::PathErr:
            return handle_path_err((unsigned char*) header);
        case RSVPHeader::ResvErr:
            return handle_resv_err((unsigned char*) header);
        case RSVPHeader::PathTear:
            return handle_path_tear((unsigned char*) header);
        case RSVPHeader::ResvTear:
            return handle_resv_tear((unsigned char*) header);
        case RSVPHeader::ResvConf:
            return handle_resv_conf((unsigned char*) header);
        default:
            ErrorHandler::default_handler()->error("RSVPHost received packet with an invalid message type");
    }

    // The packet isn't needed anymore, delete it
    packet->kill();
}

void RSVPHost::handle_path(const unsigned char *const packet) {

    // Get all the objects we need from the message
    Path path {};
    if (check(not find_path_ptrs(packet, path), "RSVPHost received an ill-formed PATH message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*path.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received PATH message that doesn't seem to belong here")) return;
    Session& session {session_pair->value};

    // If this is the first PATH message, initialise the session
    if (not session.send_data) {
        // Create a new SenderID object and add it
        session.sender = SenderID {path.sender.sender->src_addr, ntohs(path.sender.sender->src_port)};

        // Create a new SendData object here, this signals that the session has already received PATH messages
        session.send_data = new SendData {this, SessionID::from_key(session_key)};

        // Collect the PATH message's PolicyData and SenderTSpec objects and add them to the state
        for (auto iter {path.policy_data.begin()}; iter < path.policy_data.end(); ++iter) {
            session.policy_data.push_back(**iter);     // iter is a pointer to a pointer
        }
        session.t_spec = *(path.sender.tspec);
    }

    // Set the prev_hop address
    session.prev_hop = path.hop->address;   // TODO correct?
}

void RSVPHost::handle_resv(const unsigned char *const packet) {

    // Get all the objects we need from the message
    Resv resv {};
    if (check(not find_resv_ptrs(packet, resv), "RSVPHost received an ill-formed RESV message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*resv.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received RESV message that doesn't seem to belong here")) return;
    Session& session {session_pair->value};

    // Check whether there are senders registered for the session that match the RESV message's flow descriptors
    for (auto flow {resv.flow_descriptor_list.begin()}; flow < resv.flow_descriptor_list.end(); ++flow) {

        // Check whether the flow's FilterSpec object matches the local session's sender
        const uint64_t sender_key {SenderID::to_key(*flow->filter_spec)};
        if (check(sender_key != session.sender.to_key(),
                "RSVPHost received RESV message with a flow descriptor that doesn't match the sender")) return;

        // Set the hop address of this state
        session.prev_hop = resv.hop->address;

        // Check whether a RESV_CONF message is requested, if so generate and send it
        if (not resv.resv_confirm) {
            session.send_data->confirmed = true;
        }
        else if (not session.send_data->confirmed) {
            auto packet {generate_resv_conf(SessionID::from_key(session_key), session.sender, session.t_spec,
                                            *resv.resv_confirm)};
            ipencap(packet, m_address_info.in_addr(), resv.hop->address);
            output(0).push(packet);
        }
    };
}

void RSVPHost::handle_path_err(const unsigned char *const packet) {

    // Get all the objects we need from the message
    PathErr path_err {};
    if (check(not find_path_err_ptrs(packet, path_err), "RSVPHost received an ill-formed PATH_ERR message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*path_err.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received PATH_ERR message that doesn't seem to belong here")) return;
    Session & session {session_pair->value};

    // Check whether the message's sender template matches the host's sender
    const uint64_t sender_key {SenderID::to_key(*path_err.sender.sender)};
    if (check(sender_key != session.sender.to_key(),
            "RSVPHost received PATH_ERR message with a SenderTemplate object that doesn't match")) return;

    // Initialise these variables here as it can't be done inside the switch statement
    const auto err_value {ntohs(path_err.error_spec->err_value)};
    const auto ss {(uint16_t) (err_value / 0x4000)};
    StringAccum err_cause {"RSVPHost received a PATH_ERR message: "};

    // Report the error
    switch (path_err.error_spec->err_code) {

        case RSVPErrorSpec::UnknownObjectClass:
            err_cause << "sent out PATH message containing unknown object type " << *((uint8_t*) &err_value);
            break;

        case RSVPErrorSpec::UnknownCType:
            err_cause << "sent out PATH message containing an unknown C-Type " << *(((uint8_t*) &err_value) + 1);
            break;

        case RSVPErrorSpec::TrafficControlError:
            if (ss != 0) {
                err_cause << "traffic control error with value " << err_value;
                break;
            }
            err_cause << "traffic control error caused by a(n) ";
            switch (err_value) {
                case 1:
                    err_cause << "service conflict";
                    break;
                case 2:
                    err_cause << "service unsupported";
                    break;
                case 3:
                    err_cause << "bad FlowSpec value";
                    break;
                case 4:
                    err_cause << "bad TSpec value";
                    break;
                default:
                    err_cause << "unknown/invalid sub-code";
                    break;
            }
            break;

        case RSVPErrorSpec::RSVPSystemError:
            err_cause << "RSVP system error with value " << err_value;
            break;

        default:
            err_cause << "unknown/invalid error code " << path_err.error_spec->err_code << " (error value " << err_value
                    << ")";
            break;
    }
    click_chatter(err_cause.c_str());
}

void RSVPHost::handle_resv_err(const unsigned char *const packet) {

    // Get all the objects we need from the message
    ResvErr resv_err {};
    if (check(not find_resv_err_ptrs(packet, resv_err), "RSVPHost received an ill-formed RESV_ERR message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*resv_err.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received RESV_ERR message that doesn't seem to belong here")) return;
    Session & session {session_pair->value};

    // Check whether the message's sender template matches any of the host's senders
    const uint64_t sender_key {SenderID::to_key(*resv_err.flow_descriptor.filter_spec)};
    if (check(sender_key != session.sender.to_key(),
              "RSVPHost received RESV_ERR message with a SenderTemplate object that doesn't match any sender")) return;

    // Initialise these variables here as it can't be done inside the switch statement
    const auto err_value {ntohs(resv_err.error_spec->err_value)};
    const auto ss {(uint16_t) (err_value / 0x4000)};
    StringAccum err_cause {"RSVPHost received RESV_ERR message: "};

    // Report the error
    switch (resv_err.error_spec->err_code) {

        case RSVPErrorSpec::UnkownResvStyle:
            err_cause << "unknown reservation style";
            break;

        case RSVPErrorSpec::UnknownObjectClass:
            err_cause << "unknown object class number " << *(uint8_t*) &err_value;
            break;

        case RSVPErrorSpec::UnknownCType:
            err_cause << "unknown object C-type " << *(((uint8_t*) &err_value) + 1);
            break;

        case RSVPErrorSpec::API:
            err_cause << "API error code " << err_value;
            break;

        case RSVPErrorSpec::TrafficControlError:
            if (ss != 0) {
                err_cause << "traffic control error with value " << err_value;
                break;
            }
            err_cause << "traffic control error caused by a(n) ";
            switch (err_value) {
                case 1:
                    err_cause << "service conflict";
                    break;
                case 2:
                    err_cause << "service unsupported";
                    break;
                case 3:
                    err_cause << "bad FlowSpec value";
                    break;
                case 4:
                    err_cause << "bad TSpec value";
                    break;
                default:
                    err_cause << "unknown/invalid sub-code " << err_value;
                    break;
            }
            break;

        case RSVPErrorSpec::RSVPSystemError:
            err_cause << "RSVP system error with value " << err_value;
            break;

        default:
            err_cause << "unknown/invalid error code " << resv_err.error_spec->err_code;
            break;
    }
    click_chatter(err_cause.c_str());
}

void RSVPHost::handle_path_tear(const unsigned char *const packet) {

    // Get all the objects we need from the packet
    PathTear path_tear {};
    if (check(not find_path_tear_ptrs(packet, path_tear), "RSVPHost received an ill-formed PATH_TEAR message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*path_tear.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received PATH_TEAR message that doesn't seem to belong here")) return;
    Session& session {session_pair->value};

    // Check whether there is a receiver registered that matches the PATH_TEAR message's SenderTemplate object
    const uint64_t sender_key {SenderID::to_key(*path_tear.sender_template)};
    if (check(sender_key != session.sender.to_key(),
            "RSVPHost received PATH_TEAR message for a receiver that is not registered to the session")) return;

    // Remove the session
    session.refresh_timer->unschedule();
    delete session.refresh_timer;
    delete session.send_data;

    m_session_ids.erase(session.id);
    m_sessions.erase(session_key);
};

void RSVPHost::handle_resv_tear(const unsigned char *const packet) {

    // Get all the objects we need from the packet
    ResvTear resv_tear {};
    if (check(not find_resv_tear_ptrs(packet, resv_tear), "RSVPHost received an ill-formed RESV_TEAR message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*resv_tear.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received RESV_TEAR message that doesn't seem to belong here")) return;
    Session& session {session_pair->value};

    // Check whether any of the RESV_TEAR message's flow descriptors match the session's sender
    for (auto flow {resv_tear.flow_descriptor_list.begin()}; flow != resv_tear.flow_descriptor_list.end(); ++flow) {
        const uint64_t sender_key {SenderID::to_key(**flow)};
        if (check(sender_key != session.sender.to_key(),
                "RSVPHost received RESV_TEAR message for a sender that is not registered to the session")) return;

        // RESV_TEAR messages don't affect senders
        check(true, "RSVPHost received RESV_TEAR message");
    };
}

void RSVPHost::handle_resv_conf(const unsigned char *const packet) {

    // Get all the object we need from the packet
    ResvConf resv_conf {};
    if (check(not find_resv_conf_ptrs(packet, resv_conf), "RSVPHost received an ill-formed RESV_CONF message")) return;

    // Check whether the message's session matches any of the host's sessions
    const uint64_t session_key {SessionID::to_key(*resv_conf.session)};
    auto session_pair {m_sessions.find_pair(session_key)};
    if (check(not session_pair, "RSVPHost received RESV_CONF message that doesn't seem to belong here")) return;
    Session& session {session_pair->value};

    // Check whether there are receivers registered that match any of the RESV_CONF message's flow descriptors
    for (auto flow {resv_conf.flow_descriptor_list.begin()}; flow != resv_conf.flow_descriptor_list.end(); ++flow) {
        const uint64_t sender_key {SenderID::to_key(*flow->filter_spec)};

        if (check(sender_key != session.sender.to_key(),
                "RSVPHost received RESV_CONF message for a receiver that is not registered to the session")) return;

        // Mark the receiver as confirmed so outgoing RESV messages won't be requesting RESV_CONF messages anymore
        session.send_data->confirmed = true;
    };
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
    Session session {};
    session.id = session_id;
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
    Session& session {host->m_sessions.find_pair(pair->value)->value};

    // Create a new sender and set/replace the session's sender
    session.sender = SenderID {source_address, source_port};

    // Check whether this is the first sender for the session
    if (not session.refresh_timer) {
        // Indicate this session as a sender
        session.is_sender = true;

        // Add the reservation's SenderTSpec object
        auto temp {(unsigned char *) &(session.t_spec)};
        RSVPSenderTSpec::write(temp, s_bucket_rate, s_bucket_size, s_peak_rate, s_min_unit, s_max_size);

        // Create a new timer and initialise it
        session.send_data = new SendData {host, session_id};
        session.refresh_timer = new Timer {push_path, session.send_data};
        session.refresh_timer->initialize(host);
    }

    // Check whether the destination has the same address as this host, if so don't send PATH messages
    if (session_id.destination_address == host->m_address_info.in_addr()) {
        errh->warning("Registered sender to session %d with as destination address this host", id);
        return 0;
    }

    // Scheduling refresh_timer now will trigger push_path which will send a PATH message
    session.refresh_timer->schedule_now();

    errh->message("Defined session %d sender %u", id, session.sender.to_key());
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
    bool conf {true};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", id)
            .read_p("CONF", conf)
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
    Session& session {host->m_sessions.find_pair(session_id)->value};

    // Check whether the session has already received a PATH message (send_data exists)
    if (not session.send_data) {
        return errh->error("RSVPHost hasn't received any PATH messages for session %d yet", id);
    }

    // Check whether this is the first call to this handler for this session (refresh_timer exists)
    if (not session.refresh_timer) {
        // Create a new timer, initialize it and let push_resv schedule it after sending a RESV message
        session.refresh_timer = new Timer {push_resv, session.send_data};
        session.refresh_timer->initialize(host);
    }

    // (Re-)Start sending RESV message, update send_data->confirmed if necessary
    session.send_data->confirmed = not conf;
    session.refresh_timer->schedule_now();

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
    int id {0};

    // Parse the config vector
    int result {Args(vconfig, host, errh)
            .read_mp("ID", id)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // Check whether a session with the given ID does actually exist
    const auto session_pair {host->m_session_ids.find_pair(id)};
    if (not session_pair) {
        return errh->error("Session with ID %d doesn't exist", id);
    }
    const SessionID session_id {SessionID::from_key(session_pair->value)};
    Session& session {host->m_sessions.find_pair(session_pair->value)->value};

    // Send an RSVP message to notify other nodes
    if (session.is_sender) {
        // Send a PATH_TEAR message to notify other RSVP nodes
        const auto packet {host->generate_path_tear(session_id, session.sender, session.t_spec,
                                                    host->m_address_info.in_addr())};
        host->ipencap(packet, session.sender.source_address, session_id.destination_address);
        host->output(0).push(packet);

        // Remove the Session object from m_sessions and m_session_ids, and delete all its pointers
        host->m_sessions.erase(session_pair->value);
        host->m_session_ids.erase(id);

        // Delete the timer and its data if they were initialised
        if (session.refresh_timer) {
            session.refresh_timer->unschedule();
        }
    }
    else {
        // Send a RESV_TEAR message to notify other RSVP nodes
        const auto packet {host->generate_resv_tear(session_id, session.sender, session.t_spec,
                                                    host->m_address_info.in_addr())};
        host->ipencap(packet, session_id.destination_address, session.prev_hop);
        host->output(0).push(packet);

        // Stop sending RESV messages, delete the timer and its data if initialised
        if (session.refresh_timer) {
            session.refresh_timer->unschedule();
            delete session.refresh_timer;
        }
        if (session.send_data) {
            delete session.send_data;
        }
    }

    errh->message("Released reservation for session %d", id);
    return 0;
}

void RSVPHost::add_handlers() {

    add_write_handler("session", session, 0);
    add_write_handler("sender", sender, 0);
    add_write_handler("reserve", reserve, 0);
    add_write_handler("release", release, 0);
}

bool RSVPHost::resv_ff_exists(const uint64_t& sender_key, const uint64_t& session_key) {
    
    // The keys from ClassifyService are structured in a different endianness
    // Session: PORT (2) | PROTO (1) | PADDING (1) | ADDRESS (4)
    const auto dst_addr {*(((in_addr*)&session_key) + 1)};
    const auto dst_port {ntohs(*(uint16_t*)&session_key)};
    const auto proto {*(((uint8_t*)&session_key) + 2)};

    // Sender: PORT (2) | PADDING (2) | ADDRESS (4)
    const auto src_addr {*(((in_addr*)&sender_key) + 1)};
    const auto src_port {ntohs(*(uint16_t*)&sender_key)};

    // Create new session and sender keys to compare
    const auto new_session_key {(SessionID {dst_addr, dst_port, proto}).to_key()};
    const auto new_sender_key {(SenderID {src_addr, src_port}).to_key()};
    
    // Check whether there exists a session with the ID
    const auto session_pair {m_sessions.find_pair(new_session_key)};
    if (session_pair) {

        // Check whether the session's sender has the same key as the given one
        return (session_pair->value.sender.to_key() == new_sender_key);
    }
    return false;
}

void RSVPHost::push_path(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(SendData*) user_data};
    if (check(not data, "PATH message can't be sent; no timer data received")) return;
    if (check(not data->host, "PATH message can't be sent; no host received")) return;

    // Make sure the given session ID is valid
    const auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "PATH message can't be sent; invalid session ID received")) return;
    const Session session {session_pair->value};

    // Generate a new PATH message and push it
    const auto packet {data->host->generate_path(data->session_id, session.sender, R, session.t_spec)};
    data->host->ipencap(packet, session.sender.source_address, data->session_id.destination_address);
    data->host->output(0).push(packet);

    // Set the timer again (a refresh randomly in the interval [0.5R, 1.5R] is recommended in RFC 2205)
    const uint32_t refresh {click_random(0.5 * R, 1.5 * R)};
    timer->reschedule_after_msec(refresh);
}

void RSVPHost::push_resv(Timer *const timer, void *const user_data) {

    // Check whether user_data contains valid data
    const auto data {(SendData*) user_data};
    if (check(not data, "RESV message can't be sent; no timer data received")) return;
    if (check(not data->host, "RESV message can't be sent; no host received")) return;

    // Make sure the given session ID is valid
    const auto session_pair {data->host->m_sessions.find_pair(data->session_id.to_key())};
    if (check(not session_pair, "RESV message can't be sent; invalid session ID received")) return;
    const Session session {session_pair->value};

    // Generate a new RESV message and push it
    const auto packet {data->host->generate_resv(data->session_id, session.sender, R, session.t_spec,
                                                 not data->confirmed)};
    // The hop address can be the destination address as this is the only host to send RESV messages
    data->host->ipencap(packet, data->session_id.destination_address, session.prev_hop);
    data->host->output(0).push(packet);

    // Set the timer again
    const uint32_t refresh {click_random(0.5 * R, 1.5 * R)};
    timer->reschedule_after_msec(refresh);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPHost)