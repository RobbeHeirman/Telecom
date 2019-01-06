#include <click/config.h>
#include "RSVPElement.hh"
#include <click/glue.hh>
#include <arpa/inet.h>


CLICK_DECLS


bool RSVPElement::validate_message(const Packet *const packet) {

    // Check whether the IP header's version, header length, total length, protocol and checksum are valid
    const auto ip {(click_ip*) packet->data()};
    if (check(ip->ip_v != 4, "IP header has incorrect version (!= 4)")) return false;
    if (check(ip->ip_hl < 5, "IP header has impossible header length (< 5)")) return false;
    if (check(packet->length() != ntohs(ip->ip_len), "IP header has incorrect total length value")) return false;
    if (check(ip->ip_p != IP_PROTO_RSVP, "IP header has incorrect protocol (!= RSVP)")) return false;
    if (check(click_in_cksum((unsigned char*) ip, 4 * ip->ip_hl), "IP header has incorrect checksum")) return false;

    // Check whether the RSVP header is correct
    const auto rsvp {(RSVPHeader*) (((unsigned char*) ip) + 4 * ip->ip_hl)};
    if (check(rsvp->version != RSVPVersion, "RSVP header has incorrect version (!= 1)")) return false;
    if (check(rsvp->msg_type > 7, "RSVP header has incorrect message type (> 7)")) return false;
    if (check(rsvp->send_ttl < ip->ip_ttl, "RSVP header has impossible TTL (< IP TTL)")) return false;
    if (check(ntohs(rsvp->length) % 4, "RSVP header has incorrect length value (% 4)")) return false;
    if (check(ntohs(rsvp->length) != ntohs(ip->ip_len) - 4 * ip->ip_hl, "RSVP header has incorrect length value"))
        return false;
    if (check(click_in_cksum((unsigned char*) rsvp, ntohs(rsvp->length)), "RSVP header has incorrect checksum"))
        return false;

    // Iterate over each RSVP object and check their object headers
    auto object {(RSVPObject*) (rsvp + 1)};
    while ((unsigned char*) object < packet->end_data()) {

        // Check whether the object header is correct
        if (check(ntohs(ntohs(object->length)) < 4, "RSVP object has incorrect length value (< 4)")) return false;
        if (check(ntohs(object->length) % 4 != 0, "RSVP object has incorrect length value (% 4)")) return false;
        if (check(object->c_type > 2, "RSVP object has incorrect C-Type (> 2)")) return false;

        // Perform more precise checks per object type (only on the header)
        switch (object->class_num) {
            case RSVPObject::Null:
                break;
            case RSVPObject::Session:
                if (check(ntohs(object->length) != 12, "RSVP session has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP session has incorrect c-type")) return false;
                break;
            case RSVPObject::Hop:
                if (check(ntohs(object->length) != 12, "RSVP hop has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP hop has incorrect c-type")) return false;
                break;
            case RSVPObject::Integrity:
                if (check(object->c_type != 1, "RSVP integrity has incorrect c-type")) return false;
                break;
            case RSVPObject::TimeValues:
                if (check(ntohs(object->length) != 8, "RSVP time values has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP time values has incorrect c-type")) return false;
                break;
            case RSVPObject::ErrorSpec:
                if (check(ntohs(object->length) != 12, "RSVP error spec has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP error spec has incorrect c-type")) return false;
                break;
            case RSVPObject::Scope:
                if (check(object->c_type != 1, "RSVP scope has incorrect c-type")) return false;
                break;
            case RSVPObject::Style:
                if (check(ntohs(object->length) != 8, "RSVP style has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP style has incorrect c-type")) return false;
                break;
            case RSVPObject::FlowSpec:
                if (check(ntohs(object->length) != 36, "RSVP flowspec has incorrect length")) return false;
                if (check(object->c_type != 2, "RSVP flowspec has incorrect c-type")) return false;
                break;
            case RSVPObject::FilterSpec:
                if (check(ntohs(object->length) != 12, "RSVP filterspec has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP filterspec has incorrect c-type")) return false;
                break;
            case RSVPObject::SenderTemplate:
                if (check(ntohs(object->length) != 12, "RSVP sender template has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP sender template has incorrect c-type")) return false;
                break;
            case RSVPObject::SenderTSpec:
                if (check(ntohs(object->length) != 36, "RSVP sender tspec has incorrect length")) return false;
                if (check(object->c_type != 2, "RSVP sender tspec has incorrect c-type")) return false;
                break;
            case RSVPObject::PolicyData:
                if (check(object->c_type != 1, "RSVP policy data has incorrect c-type")) return false;
                break;
            case RSVPObject::ResvConfirm:
                if (check(ntohs(object->length) != 8, "RSVP resv confirm has incorrect length")) return false;
                if (check(object->c_type != 1, "RSVP resv confirm has incorrect c-type")) return false;
                break;
            default:
                check(true, "RSVP object has incorrect class number");
                return false;
        }

        // Increase the object pointer by the length (in bytes) advertised in the current object's header
        object = (RSVPObject*) (((uint8_t*) object) + ntohs(object->length));
    }

    // If all checks succeeded
    return true;
}

bool RSVPElement::find_path_ptrs(const unsigned char *const packet, Path& path) {

    // Main object to iterate over our package objects
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)}; // Ptr to the first RSVPObject

    // Make sure path is initialised properly to avoid reporting false duplicate errors
    path = Path {};
    bool ret_val = true;
    //click_chatter(String("Packet length", packet + ntohs(header->length)).c_str());
    while((const unsigned char*) object < packet + ntohs(header->length)) {

        // check for valid C-type
        if( object->c_type > 2){ // Only 2 C types legal

            click_chatter("Illegal C type in path message");
            ret_val = false;
            path.error_code = RSVPErrorSpec::UnknownCType;
            path.error_value = ((uint16_t) object->class_num << 8) | object->c_type;

        }
        // We want to handle on the type of object gets trough
        switch (object->class_num) {
            case RSVPObject::Null:
                break;

            case RSVPObject::Session:
                if (check(path.session, "PATH message contains two Session objects")) return false;
                path.session = (RSVPSession*) object; // Downcast to RSVPSession object
                break;

            case RSVPObject::Hop:
                if (check(path.hop, "PATH message contains two Hop objects")) return false;
                path.hop = (RSVPHop*) object; // We downcast to our RSVPHOP object
                break;

            case RSVPObject::TimeValues:
                if (check(path.time_values, "PATH message contains two TimeValues objects")) return false;
                path.time_values = (RSVPTimeValues*) object;
                break;

            case RSVPObject::PolicyData:
                path.policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::SenderTemplate:
                if (check(path.sender.sender, "PATH message contains two SenderTemplate objects"))
                    return false;
                path.sender.sender = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                if (check(path.sender.tspec, "PATH message contains two SenderTSpec objects")) return false;
                path.sender.tspec = (RSVPSenderTSpec*) object;
                break;

            default:
                click_chatter("PATH message contains an object with an invalid class number");
                // Still need those possible other ptr's for path error messaging
                //return false;

                path.error_code = RSVPErrorSpec::ErrorCode ::UnknownObjectClass;
                ret_val = false;
        }

        // Add the object's length advertised in its header (in bytes) to the pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory objects were present in the message
    if (check(not path.session, "PATH message is missing a Session object") or
        check(not path.hop, "PATH message is missing a Hop object") or
        check(not path.time_values, "PATH message is missing a TimeValues object") or
        check(not path.sender.sender, "PATH message is missing a SenderTemplate object") or
        check(not path.sender.tspec, "PATH message is missing a SenderTSpec object")) return false;

    // All went well
    return ret_val;
}

bool RSVPElement::find_resv_ptrs(const unsigned char *const packet, Resv& resv) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure resv is initialised properly to avoid reporting false duplicate errors
    resv = Resv {};

    // Loop until all objects except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(resv.session, "RESV message contains two Session objects")) return false;
                resv.session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(resv.hop, "RESV message contains two Hop objects")) return false;
                resv.hop = (RSVPHop*) object;
                break;

            case RSVPObject::TimeValues:
                if (check(resv.time_values, "RESV message contains two TimeValues objects")) return false;
                resv.time_values = (RSVPTimeValues*) object;
                break;

            case RSVPObject::ResvConfirm:
                if (check(resv.resv_confirm, "RESV message contains two ResvConfirm objects")) return false;
                resv.resv_confirm = (RSVPResvConfirm*) object;
                break;

            case RSVPObject::Scope:
                if (check(resv.scope, "RESV message contains two Scope objects")) return false;
                resv.scope = (RSVPScope*) object;
                break;

            case RSVPObject::PolicyData:
                resv.policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::Style:
                // As the Style objects should always come right before the flow descriptor list, stop the loop here
                keep_going = false;
                resv.style = (RSVPStyle*) object;    // (No duplicate check as this loop stops after one Style object)
                break;

            default:
                check(true, "RESV message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Variable to temporarily keep a FlowSpec object before adding it to the flow descriptor list
    RSVPFlowSpec* flow_spec {nullptr};

    // We can continue with the object pointer as we exited the previous loop after encountering a Style object
    while ((uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                break;

            case RSVPObject::FlowSpec:
                flow_spec = (RSVPFlowSpec*) object;
                break;

            case RSVPObject::FilterSpec:
                if (check(not flow_spec,
                        "RESV message contains a FilterSpec object without a preceding FlowSpec object")) return false;
                resv.flow_descriptor_list.push_back(FlowDescriptor {flow_spec, (RSVPFilterSpec*) object});
                break;

            default:
                check(true, "RESV message flow descriptor list contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory object were present in the message
    if (check(not resv.session, "RESV message is missing a Session object") or
        check(not resv.hop, "RESV message is missing a Hop object") or
        check(not resv.time_values, "RESV message is missing a TimeValues object") or
        check(not resv.style, "RESV message is missing a Style object") or
        check(resv.flow_descriptor_list.empty(), "RESV message is missing a flow descriptor list")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_path_err_ptrs(const unsigned char *const packet, PathErr& path_err) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure path_err is initialised properly to avoid reporting false duplicate errors
    path_err = PathErr {};

    // Loop until the whole package has been read
    while ((uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(path_err.session, "PATH_ERR message contains two Session objects")) return false;
                path_err.session = (RSVPSession*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(path_err.error_spec, "PATH_ERR message contains two ErrorSpec objects")) return false;
                path_err.error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::PolicyData:
                path_err.policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::SenderTemplate:
                if (check(path_err.sender.sender, "PATH_ERR message contains two SenderTemplate objects")) return false;
                path_err.sender.sender = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                if (check(path_err.sender.tspec, "PATH_ERR message contains two SenderTSpec objects")) return false;
                path_err.sender.tspec = (RSVPSenderTSpec*) object;
                break;

            default:
                check(true, "PATH_ERR message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory objects were present in the message
    if (check(not path_err.session, "PATH_ERR message is missing a Session object") or
        check(not path_err.error_spec, "PATH_ERR message is missing an ErrorSpec object") or
        check(not path_err.sender.sender, "PATH_ERR message is missing a SenderTemplate object") or
        check(not path_err.sender.tspec, "PATH_ERR message is missing a SenderTSpec object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_err_ptrs(const unsigned char *const packet, ResvErr& resv_err) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure resv_err is initialised properly to avoid reporting false duplicates
    resv_err = ResvErr {};

    // Loop until every object object except for the flow descriptor has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(resv_err.session, "RESV_ERR message contains two Session objects")) return false;
                resv_err.session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(resv_err.hop, "RESV_ERR message contains two Hop objects")) return false;
                resv_err.hop = (RSVPHop*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(resv_err.error_spec, "RESV_ERR message contains two ErrorSpec objects")) return false;
                resv_err.error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::Scope:
                if (check(resv_err.scope, "RESV_ERR message contains two Scope objects")) return false;
                resv_err.scope = (RSVPScope*) object;
                break;

            case RSVPObject::PolicyData:
                resv_err.policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::Style:
                keep_going = false;
                resv_err.style = (RSVPStyle*) object;
                break;

            default:
                check(true, "RESV_ERR message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure the next object is a FlowSpec object
    if (check(object->class_num != RSVPObject::FlowSpec,
            "RESV_ERR message Style object isn't followed by a FlowSpec object")) return false;
    resv_err.flow_descriptor.flow_spec = (RSVPFlowSpec*) (object);
    object = (RSVPObject*) (resv_err.flow_descriptor.flow_spec + 1);

    // Make sure the next object is a FilterSpec object
    if (check(object->class_num != RSVPObject::FilterSpec,
            "RESV_ERR message FlowSpec isn't followed by a FilterSpec object")) return false;
    resv_err.flow_descriptor.filter_spec = (RSVPFilterSpec*) (object);

    // Make sure all mandatory objects were present in the message
    if (check(not resv_err.session, "RESV_ERR message is missing a Session object") or
        check(not resv_err.hop, "RESV_ERR message is missing a Hop object") or
        check(not resv_err.error_spec, "RESV_ERR message is missing an ErrorSpec object") or
        check(not resv_err.style, "RESV_ERR message is missing a style object") or
        check(not resv_err.flow_descriptor.flow_spec, "RESV_ERR message is missing a FlowSpec object") or
        check(not resv_err.flow_descriptor.filter_spec, "RESV_ERR message is missing a FilterSpec object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_path_tear_ptrs(const unsigned char *const packet, PathTear& path_tear) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure path_tear is initialised properly to avoid reporting false duplicate errors
    path_tear = PathTear {};
    RSVPSenderTSpec* sender_tspec {nullptr};

    // Loop until every object has been read
    while ((uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(path_tear.session, "PATH_TEAR message contains two Session objects")) return false;
                path_tear.session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(path_tear.hop, "PATH_TEAR message contains two Hop objects")) return false;
                path_tear.hop = (RSVPHop*) object;
                break;

            case RSVPObject::SenderTemplate:
                if (check(path_tear.sender_template, "PATH_TEAR contains two SenderTemplate objects")) return false;
                path_tear.sender_template = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                // SenderTSpec objects in PATH_TEAR messages should be ignored by RSVP elements
                //   but for completeness we check for duplicates
                if (check(sender_tspec, "PATH_TEAR contains two SenderTSpec objects")) return false;
                sender_tspec = (RSVPSenderTSpec*) object;
                break;

            default:
                check(true, "PATH_TEAR contains an object with an invalid class number");
                return false;
        }

        // Add the length of the object (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory objects were present in the PATH_TEAR message
    if (check(not path_tear.session, "PATH_TEAR message is missing a Session object") or
        check(not path_tear.hop, "PATH_TEAR message is missing a Hop object") or
        check(not path_tear.sender_template, "PATH_TEAR message is missing a SenderTemplate object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_tear_ptrs(const unsigned char *const packet, ResvTear& resv_tear) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure resv_tear is properly initialised to avoid reporting false duplicate errors
    resv_tear = ResvTear {};
    RSVPScope* scope {nullptr};

    // Loop until every object except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(resv_tear.session, "RESV_TEAR message contains two Session objects")) return false;
                resv_tear.session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(resv_tear.hop, "RESV_TEAR message contains two Hop objects")) return false;
                resv_tear.hop = (RSVPHop*) object;
                break;

            case RSVPObject::Scope:
                if (check(scope, "RESV_TEAR message contains two Scope objects")) return false;
                // Scope objects can be ignored, but for completeness we make sure there are no duplicate Scope objects
                scope = (RSVPScope*) object;
                break;

            case RSVPObject::Style:
                // The loop can be stopped here as a Style object followed by a descriptor list should always be the
                //   last part of a RESV_TEAR message
                keep_going = false;
                resv_tear.style = (RSVPStyle*) object;
                break;

            default:
                check(true, "RESV_TEAR message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // We can continue with the object pointer because we didn't increase it after meeting a FlowSpec object
    while ((unsigned char*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
            case RSVPObject::FlowSpec:
                // In case of a RESV_TEAR message, not only Null but also FlowSpec objects can be ignored
                break;

            case RSVPObject::FilterSpec:
                resv_tear.flow_descriptor_list.push_back((RSVPFilterSpec*) object);
                break;

            default:
                // Other class numbers shouldn't appear (at this position) in a RESV_CONF object
                check(true, "RESV_CONF message flow descriptor list contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory objects were present in the RESV_TEAR message
    if (check(not resv_tear.session, "RESV_TEAR message is missing a Session object") or
        check(not resv_tear.hop, "RESV_TEAR message is missing a Hop object") or
        check(not resv_tear.style, "RESV_TEAR message is missing a Style object") or
        check(resv_tear.flow_descriptor_list.empty(), "RESV_TEAR message is missing a flow descriptor list")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_conf_ptrs(const unsigned char *const packet, ResvConf& resv_conf) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    const auto header {(RSVPHeader*) packet};
    auto object {skip_integrity(packet)};

    // Make sure resv_conf is properly initialised to avoid reporting false duplicate errors
    resv_conf = ResvConf {};

    // Loop until every object except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (unsigned char*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(resv_conf.session, "RESV_CONF message contains two Session objects")) return false;
                resv_conf.session = (RSVPSession*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(resv_conf.error_spec, "RESV_CONF message contains two ErrorSpec objects")) return false;
                resv_conf.error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::ResvConfirm:
                if (check(resv_conf.resv_confirm, "RESV_CONF message contains two ResvConf objects")) return false;
                resv_conf.resv_confirm = (RSVPResvConfirm*) object;
                break;

            case RSVPObject::Style:
                // The loop can be stopped here as a Style object followed by a descriptor list should always be the
                //   last part of a RESV_CONF message
                keep_going = false;
                resv_conf.style = (RSVPStyle*) object;
                break;

            case RSVPObject::FlowSpec:
                check(true, "RESV_CONF message contains a FlowSpec object without a preceding Style object");
                return false;

            case RSVPObject::FilterSpec:
                check(true, "RESV_CONF message contains a FilterSpec object without a preceding Style object");
                return false;

            default:
                // Other class numbers shouldn't appear in a RESV_CONF object
                check(true, "RESV_CONF message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // FlowSpec variable to temporarily keep an object before adding it to the flow descriptor list
    RSVPFlowSpec* flow_spec {nullptr};

    // We can continue with the object pointer because we didn't increase it after meeting a FlowSpec object
    while ((unsigned char*) object < packet + ntohs(header->length)) {
        switch (object->class_num) {

            case RSVPObject::Null:
                break;

            case RSVPObject::FlowSpec:
                flow_spec = (RSVPFlowSpec*) object;
                break;

            case RSVPObject::FilterSpec:
                if (check(not flow_spec, "RESV_CONF message flow descriptor list doesn't start with a FlowSpec object"))
                    return false;
                resv_conf.flow_descriptor_list.push_back(FlowDescriptor {flow_spec, (RSVPFilterSpec*) object});
                break;

            default:
                // Other class numbers shouldn't appear (at this position) in a RESV_CONF object
                check(true, "RESV_CONF message flow descriptor list contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // Make sure all mandatory objects were present in the message
    if (check(not resv_conf.session, "RESV_CONF message is missing a Session object") or
        check(not resv_conf.error_spec, "RESV_CONF message is missing an ErrorSpec object") or
        check(not resv_conf.resv_confirm, "RESV_CONF message is missing a ResvConfirm object") or
        check(not resv_conf.style, "RESV_CONF message is missing a Style object") or
        check(not flow_spec, "RESV_CONF message is missing a flow descriptor list") or
        check(resv_conf.flow_descriptor_list.empty(), "RESV_CONF message is missing a FilterSpec object")) return false;

    // All went well
    return true;
}

RSVPObject* RSVPElement::skip_integrity(const unsigned char *const packet) const {

    // Get the first RSVP object right after the header
    auto object {(RSVPObject*) ((RSVPHeader*) packet + 1)};

    // Check for an Integrity object which must come right after the header if included in the message
    if (object->class_num == RSVPObject::Integrity) {
        const auto integrity {(RSVPIntegrity*) object};
        object = (RSVPObject*) (integrity + 1);
    }

    return object;
}

WritablePacket* RSVPElement::generate_path(const SessionID& session_id, const SenderID& sender_id, const uint32_t R,
        const RSVPSenderTSpec& t_spec) {

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
    RSVPSenderTSpec   ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                       htonl(t_spec.m), htonl(t_spec.M));
    // Don't just copy the SenderTSpec object to make sure the object header is correct, and pos_ptr gets updated

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv(const SessionID& session_id, const SenderID& sender_id, const uint32_t R,
        const RSVPSenderTSpec& t_spec, const bool confirm) {

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
    RSVPHop       ::write(pos_ptr, m_address_info.in_addr());
    RSVPTimeValues::write(pos_ptr, R);
    if (confirm) {
        RSVPResvConfirm::write(pos_ptr, session_id.destination_address);
    }
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                   htonl(t_spec.m), htonl(t_spec.M));
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_path_err(const SessionID& session_id, const SenderID& sender_id,
        const RSVPSenderTSpec& t_spec, const RSVPErrorSpec::ErrorCode code, const uint16_t error_value) {

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
    RSVPErrorSpec     ::write(pos_ptr, m_address_info.in_addr(), 0x00, code, error_value);
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                       htonl(t_spec.m), htonl(t_spec.M));

    // Complete the header by setting the size and checksum correctly
    RSVPHeader::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv_err(const SessionID& session_id, const SenderID& sender_id,
        const RSVPSenderTSpec& t_spec, RSVPErrorSpec::ErrorCode error_code, uint16_t error_value) {

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
    RSVPHeader    ::write(pos_ptr, RSVPHeader::ResvErr);
    RSVPSession   ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop       ::write(pos_ptr, sender_id.source_address);
    RSVPErrorSpec ::write(pos_ptr, m_address_info.in_addr(), 0, error_code, error_value);
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                   htonl(t_spec.m), htonl(t_spec.M));
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_path_tear(const SessionID& session_id, const SenderID& sender_id,
        const RSVPSenderTSpec& t_spec, const in_addr hop_address) {

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
    RSVPHop           ::write(pos_ptr, hop_address);
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                       htonl(t_spec.m), htonl(t_spec.M));

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv_tear(const SessionID& session_id, const SenderID& sender_id,
        const RSVPSenderTSpec& t_spec, const in_addr hop_address) {

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader) + sizeof(RSVPSession)    + sizeof(RSVPHop)
                           + sizeof(RSVPStyle)  + sizeof(RSVPFlowSpec)   + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader    ::write(pos_ptr, RSVPHeader::ResvTear);
    RSVPSession   ::write(pos_ptr, session_id.destination_address, session_id.proto, session_id.destination_port);
    RSVPHop       ::write(pos_ptr, hop_address);
    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                   htonl(t_spec.m), htonl(t_spec.M));
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv_conf(const SessionID& session_id, const SenderID& sender_id,
        const RSVPSenderTSpec& t_spec, const RSVPResvConfirm& resv_confirm) {

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
    RSVPErrorSpec  ::write(pos_ptr, sender_id.source_address, RSVPErrorSpec::Confirmation);
    RSVPResvConfirm::write(pos_ptr, resv_confirm.rec_addr);
    RSVPStyle      ::write(pos_ptr);
    RSVPFlowSpec   ::write(pos_ptr, convert_float(t_spec.r), convert_float(t_spec.b), convert_float(t_spec.p),
                                    ntohl(t_spec.m), ntohl(t_spec.M));
    RSVPFilterSpec ::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader     ::complete(packet, size);
    return packet;
}

void RSVPElement::ipencap(Packet *const packet, const in_addr& source, const in_addr& destination) {

    click_ip* ip_header {nullptr};
    const auto size {sizeof(click_ip)};

    if (not packet->has_network_header()) {
        const auto temp = (click_ip*) packet->push(size);
        if (not temp) {
            return;
        }
    }
    ip_header = (click_ip*) packet->data();
    packet->set_ip_header(ip_header, size);
    memset(ip_header, 0, size);

    ip_header->ip_v = 4;
    ip_header->ip_hl = size / 4;
    ip_header->ip_tos = 32;
    ip_header->ip_len = htons(packet->length());
    ip_header->ip_id = 0;
    ip_header->ip_ttl = 100;
    ip_header->ip_p = IP_PROTO_RSVP;
    ip_header->ip_src = source;
    ip_header->ip_dst = destination;
    ip_header->ip_sum = click_in_cksum((unsigned char*) packet->data(), size);
}

/*uint64_t RSVPElement::session_to_key(RSVPSession *const session) {

    uint32_t ip_addr = (uint32_t) session->dest_addr.s_addr;
    uint8_t proto = session->proto;
    uint8_t flags = session->flags;
    uint16_t port = session->dest_port;

    uint16_t temp_step1 = ((uint16_t)proto << 8)| flags;
    uint32_t temp_step2 = ((uint32_t)temp_step1 << 16) | port;
    return ((uint64_t)ip_addr << 32 | temp_step2);
}

uint64_t RSVPElement::sender_template_to_key(RSVPSenderTemplate *const sender_template) {

    uint32_t ip_addr = (uint32_t) sender_template->src_addr.s_addr;
    uint16_t unused = 0;
    uint16_t src_port = sender_template->src_port;

    uint32_t temp_step1 = ((uint32_t)unused << 16) | src_port;
    return uint64_t ((uint64_t) ip_addr << 32) | temp_step1;
}
*/

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPElement)