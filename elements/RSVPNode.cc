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

    // Tell the IPEncapModule we keep on routing to the receiver
    set_ipencap(path.sender.sender->src_addr, path.session->dest_addr);
}

void RSVPNode::handle_resv_message(Packet *p, int port) {

    // Helping to find us our corresponding ptrs.
    Resv resv;
    find_resv_ptrs(p, resv);

    // We loop over all flowDescriptors
    for(auto i = 0; i < resv.flow_descriptor_list.size(); i++){

        // Since this is FF style we look for the sender corresponding with the filterspec
        uint64_t address_key = FilterSpecID::to_key(*(resv.flow_descriptor_list[i].filter_spec));
        if(m_path_state.find(address_key) != m_path_state.end()) {

            // We look for the corresponding session in our PathState Table.
            uint64_t session_key = session_to_key(resv.session);
            if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()){

                //TODO: Reservations should happen here, for now we only forward the message upstream.
                PathState &state = m_path_state[address_key][session_key];
                RSVPHeader *header = (RSVPHeader *) p->data();
                //Signaling that the IPEncap with the correct src and dst addresses.
                set_ipencap(m_interfaces[port], state.prev_hop);
            }
            else {
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



    for(int i = 0; i < resv_tear.flow_descriptor_list.size(); i++){

        // FF so we look for the (sender, session) pair
        uint64_t address_key = FilterSpecID::to_key(*resv_tear.flow_descriptor_list[i]);
        if(m_path_state.find(address_key) != m_path_state.end()) {

            uint64_t session_key = session_to_key(resv_tear.session);
            if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()) {

                // Now we found that pathstate we first make sure that we handle our IP addresses correctly.
                // So we make a copy of the Addres of NHOP.
                PathState* state = &m_path_state[address_key][session_key];
                in_addr addr = state->prev_hop;

                if(this->delete_state(address_key, session_key, state->prev_hop)){ // If it's successfully deleted.
                    RSVPHeader *header = (RSVPHeader *) p->data();
                    set_ipencap(m_interfaces[port], state->prev_hop);
                    return true;
                }

                else{ // If not we discard it.
                    p->kill();
                    return false;
                }

                // Now we have to delete this state

            }
            else {
                click_chatter("Found a NONE existing session in receiver message.");
            }

        }
        else{
            click_chatter("Found a filter spec without matching sender spec!");
        }
    }

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