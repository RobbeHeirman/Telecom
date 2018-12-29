//
// Created by robbe on 29/12/18.
//

#ifndef TELECOM_RSVPELEMENT_H
#define TELECOM_RSVPELEMENT_H

#include <click/element.hh>
#include <click/vector.hh>
#include "RSVPStructs.hh"
#include <click/error.hh>


CLICK_DECLS

/**
 * @class
 * Abstract class for RSVPElements
 */
class RSVPElement: public Element {

public:

    const char* class_name() const {return "RSVPNode";}
    const char* port_count() const {return PORTS_1_1;} // Takes a rsvp modes and handles accordingly and outputs again 1/1
    const char* processing() const {return PUSH;}

protected:
    /**
     * Helper function that will help us find package ptrs.
     * @param: Packet is a ptr to package where we want to extract the path ptrs.
     */
    void find_path_ptrs(Packet*& p, RSVPSession*& session, RSVPHop*& hop, RSVPSenderTemplate*& sender,
                        RSVPSenderTSpec*& tspec, Vector<RSVPPolicyData*>& policy_data);


    // Function that sends an error to the default handler if the condition is true
    static inline bool check(bool condition, const String& message);

};

CLICK_ENDDECLS

#endif //TELECOM_RSVPELEMENT_H
