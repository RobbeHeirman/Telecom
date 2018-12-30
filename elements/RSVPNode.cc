#include <click/config.h>
#include "RSVPNode.hh"
#include <click/args.hh>

CLICK_DECLS

RSVPNode::RSVPNode():RSVPElement() {}

int RSVPNode::configure(Vector<String>& config, ErrorHandler *const errh) {

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


void RSVPNode::push(int port, Packet* p){

    // We know a RSVP message start with the RSVP header.
    // We can cast directly.
    RSVPHeader* header = (RSVPHeader*) p->data();

    // If we receive a PATH message
    if(header->msg_type == RSVPHeader::Type::Path){
        handle_path_message(p);
    }

    else if (header->msg_type == RSVPHeader::Type::Resv){
        handle_resv_message(p);
    }
    output(port).push(p);
}

void RSVPNode::handle_path_message(Packet *p) {

    // Block of info we need to find
    Path path {};
    find_path_ptrs(p, path); // function in abstract to find path ptrs


    // "State is defined by < session, sender template>"
    // Converting packets to 64 bit words so we can use those as keys for our HashMap.
    uint64_t byte_session = this->session_to_key(path.session);
    uint64_t byte_sender = this->sender_template_to_key(path.sender.sender);

    click_chatter(String(byte_sender).c_str());
    if(m_path_state.find(byte_sender) == m_path_state.end()){
        m_path_state[byte_sender] = HashTable <uint64_t, PathState>();
    }

    if(m_path_state[byte_sender].find(byte_session) == m_path_state[byte_sender].end()){

        PathState state;
        state.prev_hop = path.hop->address;
        for(int i = 0; i < path.policy_data.size() ; i++){
            state.policy_data.push_back(*(path.policy_data[i]));
        }
        state.t_spec = *(path.sender.tspec);

        m_path_state[byte_sender][byte_session] = state;
        click_chatter("New session added!");
    }
    else{
        click_chatter("Session already active..."); // Timers need to be restarted here.
    }

    // Tell the IPEncapModule we keep on routing to the receiver
    set_ipencap(path.sender.sender->src_addr, path.session->dest_addr);
}

void RSVPNode::handle_resv_message(Packet *p) {

    // Helping to find us our corresponding ptrs.
    Resv resv;
    find_resv_ptrs(p, resv);

    // We loop over all flowDescriptors
    for(auto i = 0; i < resv.flow_descriptor_list.size(); i++){

        FlowDescriptor& descriptor{resv.flow_descriptor_list[i]};
        uint32_t src_addr =(uint32_t) descriptor.filter_spec->src_addr.s_addr;
        uint16_t port = descriptor.filter_spec->src_port;
        uint32_t none = 0;
        uint32_t extended_port = none | port ;
        uint64_t address_key = ((uint64_t)src_addr << 32 ) | extended_port;

        //click_chatter(String(IPAddress(src_addr).unparse()).c_str());

        if(m_path_state.find(address_key) != m_path_state.end()){

            uint64_t session_key = session_to_key(resv.session);
            if(m_path_state[address_key].find(session_key) != m_path_state[address_key].end()){
                click_chatter("Found it!!!");
                PathState& state = m_path_state[address_key][session_key];
                set_ipencap(resv.hop->address, state.prev_hop);
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

uint64_t RSVPNode::session_to_key(RSVPSession* session){

    uint32_t ip_addr = (uint32_t) session->dest_addr.s_addr;
    uint8_t proto = session->proto;
    uint8_t flags = session->flags;// A session is defined by the
    uint16_t port = session->dest_port;

    uint16_t temp_step1 = ((uint16_t)proto << 8)| flags;
    uint32_t temp_step2 = ((uint32_t)temp_step1 << 16) | port;
    return ((uint64_t)ip_addr << 32 | temp_step2);
}

uint64_t RSVPNode::sender_template_to_key(RSVPSenderTemplate *sender_template) {

    uint32_t ip_addr = (uint32_t) sender_template->src_addr.s_addr;
    uint16_t unused = 0;
    uint16_t src_port = sender_template->src_port;

    uint32_t temp_step1 = ((uint32_t)unused << 16) | src_port;
    return uint64_t ((uint64_t) ip_addr << 32) | temp_step1;
}



CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)