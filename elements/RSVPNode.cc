#include <click/config.h>
#include "RSVPNode.hh"
#include <click/args.hh>

CLICK_DECLS

RSVPNode::RSVPNode():RSVPElement() {}

int RSVPNode::configure(Vector<String>& config, ErrorHandler *const errh) {

    // Parse the config vector
    int result {Args(config, this, errh)
                        .read_mp("AddressInfo", m_address_info)
                        .complete()};

    // Check whether the parse failed
    if (result < 0) {
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

        RSVPObject* object = (RSVPObject*) (header + 1 ) ; // Ptr to the RSVPObject package

        // Block of info we need to find
        RSVPSession* session{nullptr};
        RSVPSenderTemplate* sender{nullptr};
        RSVPHop* hop{nullptr};
        RSVPSenderTSpec* t_spec{nullptr};
        Vector<RSVPPolicyData*> policy_data;
        find_path_ptrs(p, session, hop, sender, t_spec, policy_data); // function in abstract to find path ptrs

        // Handling the PathState (separate function)?
        PathState state;
        if(!hop == 0)
        state.prev_hop = hop->address;

        // "State is defined by < session, sender template>"
        // Converting packets to 64 bit words so we can use those as keys for our HashMap.
        uint64_t byte_session = this->session_to_key(session);
        uint64_t byte_sender = this->sender_template_to_key(sender);

        if(m_path_state.find(byte_sender) == m_path_state.end()){
            m_path_state[byte_sender] = HashTable <uint64_t, PathState>();
        }

        if(m_path_state[byte_sender].find(byte_session) == m_path_state[byte_sender].end()){
            click_chatter("New session added!");
            m_path_state[byte_sender][byte_session] = state;
        }
        else{
            click_chatter("Session already active..."); // Timers need to be restarted here.
        }

        //Writing the address in hop for next node
        hop->address = this->m_address_info;

        // Resetting the checksum because we changed the hop address
        header->checksum = 0; // checksum assumes the checksum field is 0
        header->checksum = click_in_cksum(p->data(),p->length());
        output(port).push(p);

    }

}

uint64_t RSVPNode::session_to_key(RSVPSession* session){

    uint32_t ip_addr = (uint32_t) session->dest_addr.s_addr;
    uint8_t proto = session->proto;
    uint8_t flags = 0;// A session is defined by the
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