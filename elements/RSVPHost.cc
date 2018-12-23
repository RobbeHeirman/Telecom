
#include <click/config.h>
#include "RSVPHost.hh"

#include <click/args.hh>
#include <click/glue.hh>

CLICK_DECLS

RSVPHost::RSVPHost() = default;

RSVPHost::~RSVPHost() = default;

void RSVPHost::push(int, Packet*) {}

Packet* RSVPHost::pull(int) {}

int RSVPHost::session(const String& config, Element *const element, void *const thunk, ErrorHandler *const errh) {

    // The element should be an RSVP host
    const auto host {(RSVPHost*) element};

    // Convert the config string to a vector of strings
    Vector<String> vconfig {};
    cp_argvec(config, vconfig);

    // Prepare variables for the parse results
    int session_id {0};
    uint32_t destination_address {0};
    uint16_t destination_port {0};

    // Parse the config vector
    result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_mp("DST", destination_address)
            .read_mp("PORT", destination_port)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: create new session

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
    uint32_t source_address {0};
    uint16_t source_port {0};

    // Parse the config vector
    result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_mp("SRC", source_address)
            .read_mp("PORT", source_port)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: initialise new sender

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
    result {Args(vconfig, host, errh)
            .read_mp("ID", session_id)
            .read_p("CONF", confirmation)
            .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: confirm the reservation

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
    result {Args(vconfig, host, errh)
                    .read_mp("ID", session_id)
                    .complete()};

    // Check whether the parse failed
    if (result < 0) {
        return result;
    }

    // TODO: release session

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