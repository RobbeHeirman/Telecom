//
// Created by robbe on 3/01/19.
//

#ifndef TELECOM_RSVPADJUSTTOS_HH
#define TELECOM_RSVPADJUSTTOS_HH

#include <click/element.hh>

CLICK_DECLS

class RSVPAdjustTos: public Element {

public:
    RSVPAdjustTos() = default;
    ~RSVPAdjustTos() = default;

    const char* class_name() const {return "RSVPAdjustTos";}
    const char* port_count() const {return PORTS_1_1;} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

};

CLICK_ENDDECLS

#endif //TELECOM_RSVPADJUSTTOS_HH
