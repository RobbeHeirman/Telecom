#include <click/config.h>
#include "RSVPNode.hh"
#include <click/args.hh>

CLICK_DECLS

RSVPNode::RSVPNode():RSVPElement() {}

int RSVPNode::configure(Vector<String>& config, ErrorHandler *const errh) {

    Args args(config, this, errh);
    // Parse the config vector
    IPAddress addr;
    int result {args
                        .read_mp("IPENCAP", ElementCastArg("IPEncap"), m_ipencap)
                        .read_mp("AddressInfo", addr)
                        .consume()};

    m_interfaces.push_back(addr);
    // Check whether the parse failed
    if (result < 0) {
        m_ipencap = nullptr;
        return -1;
    }

    while(!args.empty()){
        IPAddress addr;
        result = args.read_p("AddressInfo", addr).consume();
        click_chatter(String(addr.unparse()).c_str());
        m_interfaces.push_back(addr);
    }
    click_chatter(String(m_interfaces.size()).c_str());
    return 0;
}


void RSVPNode::push(int port, Packet* p){

    // We know a RSVP message start with the RSVP header.
    // We can cast directly.
    RSVPHeader* header = (RSVPHeader*) p->data();

    // If we receive a PATH message
    if(header->msg_type == RSVPHeader::Type::Path){
        handle_path_message(p, port);
    }

    else if (header->msg_type == RSVPHeader::Type::Resv){
        handle_resv_message(p, port);
    }

    else if (header->msg_type == RSVPHeader::Type::PathTear){
        if(!this->handle_path_tear_message(p, port)){ // Then the package is killed and not forwarded.
            return;
        }
    }

    else if(header->msg_type == RSVPHeader::Type::ResvTear){

    }
    output(port).push(p);
}

void RSVPNode::handle_path_message(Packet *p, int port) {
    // TODO: Timed path messages to be resend.
    // Block of info we need to find
    Path path {};
    find_path_ptrs(p, path); // function in abstract to find path ptrs


    // "State is defined by < session, sender template>"
    // Converting packets to 64 bit words so we can use those as keys for our HashMap.
    uint64_t byte_session = this->session_to_key(path.session);
    uint64_t byte_sender = this->sender_template_to_key(path.sender.sender);

    if(m_path_state.find(byte_sender) == m_path_state.end()){
        m_path_state[byte_sender] = HashTable <uint64_t, PathState>();
    }

    PathState state;
    state.prev_hop = path.hop->address;
    for(int i = 0; i < path.policy_data.size() ; i++){
        state.policy_data.push_back(*(path.policy_data[i]));
    }
    state.t_spec = *(path.sender.tspec);
    m_path_state[byte_sender][byte_session] = state;



    RSVPHeader* header= (RSVPHeader*) p ->data();
    path.hop->address = m_interfaces[port];
    header->checksum = 0;
    header->checksum = click_in_cksum(p->data(),p->length());

    // Tell the IPEncapModule we keep on routing to the receiver
    set_ipencap(path.sender.sender->src_addr, path.session->dest_addr);
}

void RSVPNode::handle_resv_message(Packet *p, int port) {

    // Helping to find us our corresponding ptrs.
    Resv resv;
    find_resv_ptrs(p, resv);

    // We loop over all flowDescriptors
    for(auto i = 0; i < resv.flow_descriptor_list.size(); i++){

        FlowDescriptor& descriptor{resv.flow_descriptor_list[i]};
        uint32_t src_addr =(uint32_t) descriptor.filter_spec->src_addr.s_addr;
        uint16_t src_port = descriptor.filter_spec->src_port;
        uint32_t none = 0;
        uint32_t extended_port = none | src_port ;
        uint64_t address_key = ((uint64_t)src_addr << 32 ) | extended_port;

        //click_chatter(String(IPAddress(src_addr).unparse()).c_str());

        if(m_path_state.find(address_key) != m_path_state.end()){

            uint64_t session_key = session_to_key(resv.session);
            if(m_path_state[address_key].find(session_key) != m_path_state[address_key].end()){
                PathState& state = m_path_state[address_key][session_key];
                RSVPHeader* header= (RSVPHeader*) p ->data();

                resv.hop->address = m_interfaces[port];
                header->checksum = 0;
                header->checksum = click_in_cksum(p->data(),p->length());

                set_ipencap(m_interfaces[port], state.prev_hop);

            }

            else{
                click_chatter("Found a NONE existing session in receiver message.");
            }
        }

        else{
            click_chatter("Found a filter spec without matching sender spec!");
        }
    }


}

bool RSVPNode::handle_path_tear_message(Packet *p, int port) {

    PathTear tear;
    find_path_tear_ptrs(p, tear);

    uint64_t sender_key = this->sender_template_to_key(tear.sender_template);
    uint64_t session_key = this->session_to_key(tear.session);

    if(delete_state(sender_key, session_key, tear.hop->address)){
        // Setting new hop
        tear.hop->address = m_interfaces[port];
        // Recalculating checksum
        RSVPHeader *header = (RSVPHeader *) p->data();
        header->checksum = 0;
        header->checksum = click_in_cksum(p->data(), p->length());
        // Tell the IPEncapModule we keep on routing to the receiver
        set_ipencap(tear.sender_template->src_addr, tear.session->dest_addr);
        return true;
    }

    else{
        p->kill(); // We did not find the session so the tear message is discarded.
        return false; // Nothing bad happend
    }

}

bool RSVPNode::handle_resv_tear_message(Packet* p, int port){

    ResvTear resv_tear;
    find_resv_tear_ptrs(p, resv_tear);

    return true;

}
bool RSVPNode::handle_path_error_message(Packet* p, int port){
    // TODO:

    return true;
}
bool RSVPNode::handle_resv_error_message(Packet* p, int port){
    // TODO:

    return true;
}
bool RSVPNode::handle_confirmation_message(Packet* p, int port){
    // TODO:
    return true;
}

bool RSVPNode::delete_state(const uint64_t& sender_key, const uint64_t& session_key, const in_addr& prev_hop){

    if(this->m_path_state.find(sender_key) != this->m_path_state.end()) {
        if (this->m_path_state[sender_key].find(session_key) != this->m_path_state[session_key].end()) {
            if (prev_hop == (m_path_state[sender_key][session_key]).prev_hop.in_addr()) { // if the hop is different no effect
                click_chatter(String("Erasing session: ", session_key).c_str());
                this->m_path_state[sender_key].erase(session_key);

                if(this->m_path_state[sender_key].empty()){
                    this->m_path_state.erase(sender_key);
                }
                return true;
            }
        }
    }

    return false;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)