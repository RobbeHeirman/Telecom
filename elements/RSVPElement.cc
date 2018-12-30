#include <click/config.h>
#include "RSVPElement.hh"
#include <click/glue.hh>
#include <arpa/inet.h>


CLICK_DECLS


bool RSVPElement::find_path_ptrs(const Packet* packet,
                                 RSVPSession*& session,
                                 RSVPHop*& hop,
                                 RSVPTimeValues*& time_values,
                                 RSVPSenderTemplate*& sender,
                                 RSVPSenderTSpec*& tspec,
                                 Vector<RSVPPolicyData*>& policy_data){

    // Main object to iterate over our package objects
    auto object {skip_integrity(packet)}; // Ptr to the RSVPObject package

    // Set all pointers to nullpointers to avoid reporting false duplicate objects
    session = nullptr;
    hop = nullptr;
    time_values = nullptr;
    sender = nullptr;
    tspec = nullptr;
    policy_data.clear();

    while((const unsigned char*) object < packet->end_data()) {
        // We want to handle on the type of object gets trough
        switch (object->class_num){

            case RSVPObject::Null : {
                break;
            }
            case RSVPObject::Session : {
                if (check(session, "PATH message contains two Session objects")) return false;
                session = (RSVPSession*) object; // Downcast to RSVPSession object
                break;
            }
            case RSVPObject::Hop : {
                if (check(hop, "PATH message contains two Hop objects")) return false;
                hop = (RSVPHop*) object; // We downcast to our RSVPHOP object
                break;
            }
            case RSVPObject::TimeValues : {
                if (check(time_values, "PATH message contains two TimeValues objects")) return false;
                time_values = (RSVPTimeValues*) object;
                break;
            }
            case RSVPObject::PolicyData : {
                RSVPPolicyData* p_data = (RSVPPolicyData*) object;
                policy_data.push_back(p_data);
                break;
            }
            case RSVPObject::SenderTemplate : {
                if (check(sender, "PATH message contains two SenderTemplate objects")) return false;
                sender = (RSVPSenderTemplate*) object;
                break;
            }
            case RSVPObject::SenderTSpec : {
                if (check(tspec, "PATH message contains two SenderTSpec objects")) return false;
                tspec = (RSVPSenderTSpec*) object;
                break;
            }
            default: {
                click_chatter("PATH message contains an object with an invalid class number");
                return false;
            }
        }

        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    if (check(not session, "PATH message is missing a Session object")) return false;
    if (check(not hop, "PATH message is missing a Hop object")) return false;
    if (check(not time, "PATH message is missing a TimeValues object")) return false;
    if (check(not sender, "PATH message is missing a SenderTemplate object")) return false;
    if (check(not tspec, "PATH message is missing a SenderTSpec object")) return false;

    return true;
}


bool RSVPElement::find_resv_ptrs(const Packet *const packet,
                                 RSVPSession*& session,
                                 RSVPHop*& hop,
                                 RSVPTimeValues*& time_values,
                                 RSVPResvConfirm*& resv_confirm,
                                 RSVPScope*& scope,
                                 Vector<RSVPPolicyData*>& policy_data,
                                 RSVPStyle*& style,
                                 Vector<FlowDescriptor>& flow_descriptor_list) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure all pointers are set to nullptr to avoid reporting false duplicates
    session = nullptr;
    hop = nullptr;
    time_values = nullptr;
    resv_confirm = nullptr;
    scope = nullptr;
    policy_data.clear();
    style = nullptr;
    flow_descriptor_list.clear();

    // Loop until all objects except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "RESV message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(hop, "RESV message contains two Hop objects")) return false;
                hop = (RSVPHop*) object;
                break;

            case RSVPObject::TimeValues:
                if (check(time_values, "RESV message contains two TimeValues objects")) return false;
                time_values = (RSVPTimeValues*) object;
                break;

            case RSVPObject::ResvConfirm:
                if (check(resv_confirm, "RESV message contains two ResvConfirm objects")) return false;
                resv_confirm = (RSVPResvConfirm*) object;
                break;

            case RSVPObject::Scope:
                if (check(scope, "RESV message contains two Scope objects")) return false;
                scope = (RSVPScope*) object;
                break;

            case RSVPObject::PolicyData:
                policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::Style:
                // As the Style objects should always come right before the flow descriptor list, stop the loop here
                keep_going = false;
                style = (RSVPStyle*) object;    // (No duplicate check as this loop stops after one Style object)
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
    while ((uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                break;

            case RSVPObject::FlowSpec:
                flow_spec = (RSVPFlowSpec*) object;
                break;

            case RSVPObject::FilterSpec:
                if (check(not flow_spec,
                        "RESV message contains a FilterSpec object without a preceding FlowSpec object")) return false;
                flow_descriptor_list.push_back(FlowDescriptor {flow_spec, (RSVPFilterSpec*) object});
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
    if (check(not session, "RESV message is missing a Session object")) return false;
    if (check(not hop, "RESV message is missing a Hop object")) return false;
    if (check(not time_values, "RESV message is missing a TimeValues object")) return false;
    if (check(not style, "RESV message is missing a Style object")) return false;
    if (check(flow_descriptor_list.empty(), "RESV message is missing a flow descriptor list")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_path_err_ptrs(const Packet *const packet,
                                     RSVPSession*& session,
                                     RSVPErrorSpec*& error_spec,
                                     Vector<RSVPPolicyData*>& policy_data,
                                     SenderDescriptor& sender_descriptor) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure all pointers are set to nullptr to avoid reporting false duplicates
    session = nullptr;
    error_spec = nullptr;
    policy_data.clear();
    sender_descriptor = {nullptr, nullptr};

    // Loop until the whole package has been read
    while ((uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "PATH_ERR message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(error_spec, "PATH_ERR message contains two ErrorSpec objects")) return false;
                error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::PolicyData:
                policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::SenderTemplate:
                if (check(sender_descriptor.sender_template, "PATH_ERR message contains two SenderTemplate objects"))
                    return false;
                sender_descriptor.sender_template = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                if (check(sender_descriptor.sender_tspec, "PATH_ERR message contains two SenderTSpec objects"))
                    return false;
                sender_descriptor.sender_tspec = (RSVPSenderTSpec*) object;
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
    if (check(not session, "PATH_ERR message is missing a Session object")) return false;
    if (check(not error_spec, "PATH_ERR message is missing an ErrorSpec object")) return false;
    if (check(not sender_descriptor.sender_template, "PATH_ERR message is missing a SenderTemplate object")) return false;
    if (check(not sender_descriptor.sender_tspec, "PATH_ERR message is missing a SenderTSpec object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_err_ptrs(const Packet *const packet,
                                     RSVPSession*& session,
                                     RSVPHop*& hop,
                                     RSVPErrorSpec*& error_spec,
//                                     RSVPScope*& scope,
                                     Vector<RSVPPolicyData*>& policy_data,
                                     RSVPStyle*& style,
                                     FlowDescriptor& flow_descriptor) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure the pointers are initialised to nullpointers to avoid reporting false duplicates
    session = nullptr;
    hop = nullptr;
    error_spec = nullptr;
    RSVPScope* scope {nullptr};
    policy_data.clear();
    style = nullptr;
    flow_descriptor = {nullptr, nullptr};

    // Loop until every object object except for the flow descriptor has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "RESV_ERR message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(hop, "RESV_ERR message contains two Hop objects")) return false;
                hop = (RSVPHop*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(error_spec, "RESV_ERR message contains two ErrorSpec objects")) return false;
                error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::Scope:
                if (check(scope, "RESV_ERR message contains two Scope objects")) return false;
                scope = (RSVPScope*) object;
                break;

            case RSVPObject::PolicyData:
                policy_data.push_back((RSVPPolicyData*) object);
                break;

            case RSVPObject::Style:
                keep_going = false;
                style = (RSVPStyle*) object;
                break;

            default:
                check(true, "RESV_ERR message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // TODO skip Null objects?

    // Make sure the next object is a FlowSpec object
    if (check(object->class_num != RSVPObject::FlowSpec,
            "RESV_ERR message Style object isn't followed by a FlowSpec object")) return false;
    flow_descriptor.flow_spec = (RSVPFlowSpec*) (object);

    // Make sure the next object is a FilterSpec object
    if (check(object->class_num != RSVPObject::FilterSpec,
            "RESV_ERR message FlowSpec isn't followed by a FilterSpec object")) return false;
    flow_descriptor.filter_spec = (RSVPFilterSpec*) (flow_descriptor.flow_spec + 1);

    // Make sure all mandatory objects were present in the message
    if (check(not session, "RESV_ERR message is missing a Session object")) return false;
    if (check(not hop, "RESV_ERR message is missing a Hop object")) return false;
    if (check(not error_spec, "RESV_ERR message is missing an ErrorSpec object")) return false;
    if (check(not style, "RESV_ERR message is missing a style object")) return false;
    if (check(not flow_descriptor.flow_spec, "RESV_ERR message is missing a FlowSpec object")) return false;
    if (check(not flow_descriptor.filter_spec, "RESV_ERR message is missing a FilterSpec object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_path_tear_ptrs(const Packet *const packet,
                                      RSVPSession*& session,
                                      RSVPHop*& hop,
                                      RSVPSenderTemplate*& sender_template) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure all pointers are set to nullptr to avoid reporting false duplicates
    session = nullptr;
    hop = nullptr;
    sender_template = nullptr;
    RSVPSenderTSpec* sender_tspec {nullptr};

    // Loop until every object has been read
    while ((uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "PATH_TEAR message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(hop, "PATH_TEAR message contains two Hop objects")) return false;
                hop = (RSVPHop*) object;
                break;

            case RSVPObject::SenderTemplate:
                if (check(sender_template, "PATH_TEAR contains two SenderTemplate objects")) return false;
                sender_template = (RSVPSenderTemplate*) object;
                break;

            case RSVPObject::SenderTSpec:
                // SenderTSpec objects should be ignored by RSVP elements but for completeness we check for duplicates
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
    if (check(session, "PATH_TEAR message is missing a Session object")) return false;
    if (check(hop, "PATH_TEAR message is missing a Hop object")) return false;
    if (check(sender_template, "PATH_TEAR message is missing a SenderTemplate object")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_tear_ptrs(const Packet *const packet,
                                      RSVPSession*& session,
                                      RSVPHop*& hop,
                                      RSVPStyle*& style,
                                      Vector<RSVPFilterSpec*>& filter_specs) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure all pointers are set to nullptr to avoid reporting false duplicates
    session = nullptr;
    hop = nullptr;
    RSVPScope* scope {nullptr};
    style = nullptr;
    filter_specs.clear();

    // Loop until every object except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (uint8_t*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "RESV_TEAR message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::Hop:
                if (check(hop, "RESV_TEAR message contains two Hop objects")) return false;
                hop = (RSVPHop*) object;
                break;

            case RSVPObject::Scope:
                if (check(scope, "RESV_TEAR message contains two Scope objects")) return false;
                // Scope objects can be ignored, but for completeness we make sure there are no duplicate Scope objects
                break;

            case RSVPObject::Style:
                // The loop can be stopped here as a Style object followed by a descriptor list should always be the
                //   last part of a RESV_TEAR message
                keep_going = false;
                style = (RSVPStyle*) object;
                break;

            default:
                check(true, "RESV_TEAR message contains an object with an invalid class number");
                return false;
        }

        // Add the length advertised in the object header (in bytes) to the object pointer
        const auto byte_pointer {(uint8_t*) object};
        object = (RSVPObject*) (byte_pointer + ntohs(object->length));
    }

    // If keep_going is still true, no Style object has been encountered and we've read the whole packet
    if (check(keep_going, "RSVP_TEAR message is missing a Style object")) return false;

    // We can continue with the object pointer because we didn't increase it after meeting a FlowSpec object
    while ((unsigned char*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
            case RSVPObject::FlowSpec:
                // In case of a RESV_TEAR message, not only Null but also FlowSpec objects can be ignored
                break;

            case RSVPObject::FilterSpec:
                filter_specs.push_back((RSVPFilterSpec*) object);
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
    if (check(not session, "RESV_TEAR message is missing a Session object")) return false;
    if (check(not hop, "RESV_TEAR message is missing a Hop object")) return false;
    if (check(not style, "RESV_TEAR message is missing a Style object")) return false;
    if (check(filter_specs.empty(), "RESV_TEAR message is missing a flow descriptor list")) return false;

    // All went well
    return true;
}

bool RSVPElement::find_resv_conf_ptrs(const Packet *const packet,
                                      RSVPSession*& session,
                                      RSVPErrorSpec*& error_spec,
                                      RSVPResvConfirm*& resv_confirm,
                                      RSVPStyle*& style,
                                      Vector<FlowDescriptor>& flow_descriptor_list) {

    // Get the first RSVP object after the header and the Integrity object (if included)
    auto object {skip_integrity(packet)};

    // Make sure the pointers are initialy nullpointers to avoid false duplicate errors
    session = nullptr;
    error_spec = nullptr;
    resv_confirm = nullptr;
    style = nullptr;
    flow_descriptor_list.clear();

    // Loop until every object except for the flow descriptor list has been read
    bool keep_going {true};
    while (keep_going and (unsigned char*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // Null objects should be ignored
                break;

            case RSVPObject::Session:
                if (check(session, "RESV_CONF message contains two Session objects")) return false;
                session = (RSVPSession*) object;
                break;

            case RSVPObject::ErrorSpec:
                if (check(error_spec, "RESV_CONF message contains two ErrorSpec objects")) return false;
                error_spec = (RSVPErrorSpec*) object;
                break;

            case RSVPObject::ResvConfirm:
                if (check(resv_confirm, "RESV_CONF message contains two ResvConf objects")) return false;
                resv_confirm = (RSVPResvConfirm*) object;
                break;

            case RSVPObject::Style:
                // The loop can be stopped here as a Style object followed by a descriptor list should always be the
                //   last part of a RESV_CONF message
                keep_going = false;
                style = (RSVPStyle*) object;
                return false;

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
    while ((unsigned char*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                break;

            case RSVPObject::FlowSpec:
                flow_spec = (RSVPFlowSpec*) object;
                break;

            case RSVPObject::FilterSpec:
                if (check(not flow_spec, "RESV_CONF message flow descriptor list doesn't start with a FlowSpec object"))
                    return false;
                flow_descriptor_list.push_back(FlowDescriptor {flow_spec, (RSVPFilterSpec*) object});
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
    if (check(not session, "RESV_CONF message is missing a Session object")) return false;
    if (check(not error_spec, "RESV_CONF message is missing an ErrorSpec object")) return false;
    if (check(not resv_confirm, "RESV_CONF message is missing a ResvConfirm object")) return false;
    if (check(not style, "RESV_CONF message is missing a Style object")) return false;
    if (check(not flow_spec, "RESV_CONF message is missing a flow descriptor list")) return false;
    if (check(flow_descriptor_list.empty(), "RESV_CONF message is missing a FilterSpec object")) return false;

    // All went well
    return true;
}

RSVPObject* RSVPElement::skip_integrity(const Packet *const packet) const {

    // Get the first RSVP object right after the header
    const auto header {(RSVPHeader*) (packet->data())};
    auto object {(RSVPObject*) (header + 1)};

    // Check for an Integrity object which must come right after the header if included in the message
    if (object->class_num == RSVPObject::Integrity) {
        const auto integrity {(RSVPIntegrity*) object};
        object = (RSVPObject*) (integrity + 1);
    }

    return object;
}

WritablePacket* RSVPElement::generate_path_err(const SessionID& session_id, const FlowID& sender_id) {

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
    RSVPErrorSpec     ::write(pos_ptr, m_address_info.in_addr(), 0x00);
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, 0.0, 0.0, 0.0, 0, 0);
    // TODO copy template and tspec from PATH message

    // Complete the header by setting the size and checksum correctly
    RSVPHeader::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv_err(const SessionID& session_id, const FlowID& sender_id) {

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
    RSVPErrorSpec ::write(pos_ptr, m_address_info.in_addr(), 0x00);
    RSVPStyle     ::write(pos_ptr);
    // TODO copy style from RESV message
    RSVPFlowSpec  ::write(pos_ptr, 0.0, 0.0, 0.0, 0, 0);    // TODO
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader   ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_path_tear(const SessionID& session_id, const FlowID& sender_id) {

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
    RSVPHop           ::write(pos_ptr, m_address_info.in_addr());
    RSVPSenderTemplate::write(pos_ptr, sender_id.source_address, sender_id.source_port);
    RSVPSenderTSpec   ::write(pos_ptr, 0.0, 0.0, 0.0, 0, 0);    // TODO

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPElement::generate_resv_tear(const SessionID& session_id, const FlowID& sender_id) {

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
    RSVPHop       ::write(pos_ptr, m_address_info.in_addr());
    RSVPStyle     ::write(pos_ptr);
    RSVPFilterSpec::write(pos_ptr, sender_id.source_address, sender_id.source_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

void RSVPElement::set_ipencap(const in_addr& source, const in_addr& destination) {

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


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPElement)