#include <click/config.h>
#include "RSVPNode.hh"

CLICK_DECLS


void RSVPNode::push(int port, Packet* p){

    // We know a RSVP message start with the RSVP header.
    // We can cast directly.
    RSVPHeader* header = (RSVPHeader*) p->data();



    // If we receive a PATH message
    if(header->msg_type == RSVPHeader::Type::Path){
        RSVPObject* session = (RSVPObject*) (header + 1 ) ;

        while((const unsigned  char*)session < p->end_data()){

            if(session->class_num == RSVPObject::Class::Session){
                click_chatter("YAY");
            }
            session = (RSVPObject*) (session + 1);
        }
    click_chatter("I have reached the end");

    }
    output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)