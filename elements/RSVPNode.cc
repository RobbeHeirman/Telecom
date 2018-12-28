#include <click/config.h>
#include <click/args.hh>
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
        unsigned int session;
        IPAddress addr_prev_hop; //the address of the previous hop needed to save the path state

        while((const unsigned  char*)object < p->end_data()){

            // We want to handle on the type of object gets trough
            switch (object->class_num){
                case RSVPObject::Class::Session : {

                    RSVPSession* session = (RSVPSession*) object; // Downcast to RSVPSession object
                    break;
                }
                case RSVPObject::Class::Hop : {

                    click_chatter(String(m_address_info.unparse()).c_str()); // TODO: address needs to be placed at hop
                    RSVPHop *hop = (RSVPHop *) object; // We downcast to our RSVPHOP object

                    addr_prev_hop = IPAddress(hop->address);
                    click_chatter(String(addr_prev_hop.unparse()).c_str());

                    break;
                }
                default:
                    break;
            }

            // Go to the next RSVPObject
            object = (RSVPObject*) (object + 1);

        }
        click_chatter("I have reached the end");

    }
    output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)