#include <click/config.h>
#include "RSVPNode.hh"


CLICK_DECLS


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
        RSVPSession* session = 0;
        RSVPSenderTemplate* sender = 0;
        IPAddress addr_prev_hop; //the address of the previous hop needed to save the path state

        while((const unsigned  char*)object < p->end_data()){

            // We want to handle on the type of object gets trough
            switch (object->class_num){
                case RSVPObject::Class::Session : {
                    if(session != 0){click_chatter("More then one session object");} // TODO: error msg?
                    session = (RSVPSession*) object; // Downcast to RSVPSession object
                    object = (RSVPObject*) (session + 1);
                    break;
                }
                case RSVPObject::Class::Hop : {

                    RSVPHop *hop = (RSVPHop *) object; // We downcast to our RSVPHOP object
                    addr_prev_hop = IPAddress(hop->address);
                    object = (object*)( hop + 1);
                    break;
                }

                case RSVPObject::Class::SenderTemplate : {
                    click_chatter(String(object->class_num).c_str());
                    if(sender != 0){click_chatter("More the one sender template");}
                    sender = (RSVPSenderTemplate*) object;
                    click_chatter(String(sender->src_port).c_str());
                    break;
                }
                default:
                    object = (RSVPObject*) (object + 1);
                    break;
            }

            // Go to the next RSVPObject


        }

        uint64_t byte_session = this->session_to_bit(session);
        uint64_t byte_sender = this->sender_template_to_bit(sender);

        if(m_path_state.find(byte_sender) == m_path_state.end()){
            click_chatter("Sender should be added");
        }
        else{
            click_chatter("Something else");
        }

    }
    output(port).push(p);


}

uint64_t RSVPNode::session_to_bit(RSVPSession* session){

    uint32_t ip_addr = (uint32_t) session->dest_addr.s_addr;
    uint8_t proto = session->proto;
    uint8_t flags = (uint8_t) session->flags; // TODO: do we care about proto and flags? I think so...
    uint16_t port = session->dest_port;

    uint16_t temp_step1 = ((uint16_t)proto << 8)| flags;
    uint32_t temp_step2 = ((uint32_t)temp_step1 << 16) | port;
    return ((uint64_t)ip_addr << 32 | temp_step2);
}

uint64_t RSVPNode::sender_template_to_bit(RSVPSenderTemplate *sender_template) {

    uint32_t ip_addr = (uint32_t) sender_template->src_addr.s_addr;
    uint16_t unused = 0;
    uint16_t src_port = sender_template->src_port;

    uint32_t temp_step1 = ((uint32_t)unused << 16) | src_port;
    return uint64_t ((uint64_t) ip_addr << 32) | temp_step1;
}



CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)