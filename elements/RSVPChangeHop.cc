#include <click/config.h>
#include <click/args.hh>

#include "RSVPChangeHop.hh"

CLICK_DECLS

int RSVPChangeHop::configure(Vector<String>& config, ErrorHandler* errh){

    int result {Args(config, this, errh).read_mp("AddressInfo", m_address_info).consume()};
    // Check whether the parse failed
    if (result < 0) {
        return -1;
    }
    return 0;
}

void RSVPChangeHop::push(int port, Packet* p){
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};
    RSVPHop* hop = this->find_hop(p);

    if(hop != nullptr){
        click_chatter("Changing Hop value to %s ", m_address_info.unparse().c_str());
        hop->address = this->m_address_info;
        header->checksum = 0;
        header->checksum = click_in_cksum(p->data(),p->length());
    }
    output(port).push(p);
}



RSVPHop* RSVPChangeHop::find_hop(Packet* p){

    // Main object to iterate over our package objects
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};
    RSVPObject* object = (RSVPObject*) (header + 1 ) ; // Ptr to the RSVPObject package
    RSVPHop* hop {nullptr};
    while((const unsigned  char*)object < p->end_data() and hop == nullptr){
        // We want to handle on the type of object gets trough
        switch (object->class_num){
            case RSVPObject::Integrity: {
                auto integrity = (RSVPIntegrity*) (object);
                object = (RSVPObject*) (integrity + 1);
                break;
            }
            case RSVPObject::Class::Session : {
                auto session = (RSVPSession*) object; // Downcast to RSVPSession object
                object = (RSVPObject*) (session + 1);
                break;
            }
            case RSVPObject::Class::Hop : {
                hop = (RSVPHop*) object; // We downcast to our RSVPHOP object
                object = (RSVPObject*)( hop + 1);
                break;
            }

            case RSVPObject::Class::TimeValues : {
                auto time = (RSVPTimeValues*) object;
                object = (RSVPObject*) (time + 1);
                break;
            }
            case RSVPObject::Class ::PolicyData : {
                RSVPPolicyData* p_data = (RSVPPolicyData*) object;
                object = (RSVPObject*) (p_data + 1);
                break;
            }
            case RSVPObject::Class::SenderTemplate : {
                auto sender = (RSVPSenderTemplate*) object;
                object = (RSVPObject*) (sender + 1);
                break;
            }
            case RSVPObject::Class::SenderTSpec : {
                auto tspec = (RSVPSenderTSpec*) object;
                object = (RSVPObject*) (tspec + 1);
                break;
            }
            default:
                //click_chatter("SHOULDN't HAPPEN!");
                //click_chatter("Faulty Number is %s: ", String(object->class_num).c_str());
                object = (RSVPObject*) (object + 1);
                break;
        }
    }
    return hop;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPChangeHop)