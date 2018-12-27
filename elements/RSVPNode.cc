#include <click/config.h>
#include "RSVPNode.hh"

CLICK_DECLS


void RSVPNode::push(int port, Packet* p){

    click_chatter("Hello World");
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)