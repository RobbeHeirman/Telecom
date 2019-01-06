//
// Created by robbe on 3/01/19.
//

#ifndef TELECOM_RSVPCLASSIFYSERVICE_HH
#define TELECOM_RSVPCLASSIFYSERVICE_HH

#include "RSVPElement.hh"

CLICK_DECLS

class RSVPClassifyService: public Element {

public:
     RSVPClassifyService() = default;
    ~RSVPClassifyService() = default;

    const char* class_name() const {return "RSVPClassifyService";}
    const char* port_count() const {return "1/2";} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

    int configure(Vector<String>& config, ErrorHandler* errh);
    void push(int port, Packet* p);

private:
    RSVPElement* m_element;

};

CLICK_ENDDECLS

#endif //TELECOM_RSVPADJUSTTOS_HH
