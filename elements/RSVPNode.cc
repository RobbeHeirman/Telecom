#include <click/config.h>
#include "RSVPNode.hh"

CLICK_DECLS


void RSVPNode::push(int port, Packet* p){

    RSVPHeader* start_header = (RSVPHeader*) p->data();
    if(start_header->msg_type == 1){
        click_chatter("yaaay");
    }
    output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)