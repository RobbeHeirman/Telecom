#include <click/config.h>
#include <click/args.hh>
#include "RSVPClassifyService.hh"

CLICK_DECLS


int RSVPClassifyService::configure(Vector<String>& config, ErrorHandler* errh){

    int result = Args(config, this, errh).read("RSVPNode", ElementCastArg("RSVPNode"), m_node).complete();

    if(result < 0){
        return result;
    }

    return 0;

}


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPClassifyService)