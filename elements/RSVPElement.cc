#include <click/config.h>
#include "RSVPElement.hh"
#include <click/glue.hh>
#include <arpa/inet.h>


CLICK_DECLS


void RSVPElement::find_path_ptrs(Packet*& p, RSVPSession*& session, RSVPHop*& hop, RSVPSenderTemplate*& sender,
                    RSVPSenderTSpec*& tspec, Vector<RSVPPolicyData*>& policy_data){

    // Main object to iterate over our package objects
    RSVPHeader* header = (RSVPHeader*) p->data();
    RSVPObject* object = (RSVPObject*) (header + 1 ) ; // Ptr to the RSVPObject package
    RSVPTimeValues* time;
    while((const unsigned  char*)object < p->end_data()){
        // We want to handle on the type of object gets trough
        switch (object->class_num){
            case RSVPObject::Integrity: {
                click_chatter("INTEGRITY is ignored");
                auto integrity = (RSVPIntegrity*) (object);
                object = (RSVPObject*) (integrity + 1);
                break;
            }
            case RSVPObject::Class::Session : {
                if(session != 0){click_chatter("More then one session object");} // TODO: error msg?
                session = (RSVPSession*) object; // Downcast to RSVPSession object
                object = (RSVPObject*) (session + 1);
                break;
            }
            case RSVPObject::Class::Hop : {
                if(hop != 0){click_chatter("More then one hop element");}
                hop = (RSVPHop *) object; // We downcast to our RSVPHOP object
                object = (RSVPObject*)( hop + 1);
                break;
            }

            case RSVPObject::Class::TimeValues : {
                time = (RSVPTimeValues*) object;
                object = (RSVPObject*) (time + 1);
                break;
            }
            case RSVPObject::Class ::PolicyData : {
                RSVPPolicyData* p_data = (RSVPPolicyData*) object;
                policy_data.push_back(p_data);
                object = (RSVPObject*) (p_data + 1);
                break;
            }
            case RSVPObject::Class::SenderTemplate : {
                if(sender != 0){click_chatter("More the one sender template");}
                sender = (RSVPSenderTemplate*) object;
                object = (RSVPObject*) (sender + 1);
                break;
            }
            case RSVPObject::Class::SenderTSpec : {
                tspec = (RSVPSenderTSpec*) object;
                object = (RSVPObject*) (tspec + 1);
                break;
            }
            default:
                click_chatter("SHOULDN't HAPPEN!");
                object = (RSVPObject*) (object + 1);
                break;
        }
    }

    if (check(not session, "RSVPHost received Path message without session object")) return;
    if (check(not hop, "RSVPHost received Path message without hop object")) return;
    if (check(not time, "RSVPHost received Path message without time values object")) return;
    if (check(not sender, "RSVPHost received Path message without SenderTemplate object")) return;
    if (check(not tspec, "RSVPHost received Path message without tspec object")) return;
}

bool RSVPElement::find_resv_conf_ptrs(const Packet *const packet,
                                      RSVPSession*& session,
                                      RSVPErrorSpec*& error_spec,
                                      RSVPResvConfirm*& resv_confirm,
                                      RSVPStyle*& style,
                                      Vector<FlowDescriptor>& flow_descriptor_list) {

    // Assuming the header doesn't contain errors and the message is in fact a RESV_CONF message, get the first object
    const auto header {(RSVPHeader*) packet->data()};
    RSVPObject* object {(RSVPObject*) (header + 1)};

    // Check for an integrity object which must come right after the header if included in the message
    if (object->class_num == RSVPObject::Integrity) {
        const auto integrity {(RSVPIntegrity*) object};
        object = (RSVPObject*) (integrity + 1);
    }

    // Make sure the pointers are initialy nullpointers to avoid false duplicate errors
    session = nullptr;
    error_spec = nullptr;
    resv_confirm = nullptr;
    style = nullptr;
    flow_descriptor_list.clear();

    // FlowSpec variable to temporarily keep an object before adding it to the flow descriptor list
    RSVPFlowSpec* flow_spec {nullptr};

    // Loop until the whole packet and every object has been read
    while ((const unsigned char*) object < packet->end_data()) {
        switch (object->class_num) {

            case RSVPObject::Null:
                // In case of a Null object, simply ignore the indicated length of the object
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

            case RSVPObject::FlowSpec:
                flow_spec = (RSVPFlowSpec*) object;
                break;

            case RSVPObject::FilterSpec:
                if (check(not flow_spec, "RESV_CONF message contains a FilterSpec object before a FlowSpec object"))
                    return false;
                flow_descriptor_list.push_back(FlowDescriptor {flow_spec, (RSVPFilterSpec*) object});
                break;

            default:
                // Other class numbers shouldn't appear in a RESV_CONF object
                check(true, "RESV_CONF message contains an object with an invalid class number");
                return false;
        }
        object = (RSVPObject*) ((unsigned char*)(object) + object->length);
    }

    // Make sure all mandatory objects were present in the message
    if (check(not session, "RESV_CONF message is missing a Session object")) return false;
    if (check(not error_spec, "RESV_CONF message is missing an ErrorSpec object")) return false;
    if (check(not resv_confirm, "RESV_CONF message is missing a ResvConfirm object")) return false;
    if (check(not style, "RESV_CONF message is missing a Style object")) return false;
    if (check(not flow_spec, "RESV_CONF message is missing a flow descriptor")) return false;
    if (check(flow_descriptor_list.empty(), "RESV_CONF is missing a FilterSpec object")) return false;

    // All went well
    return true;
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