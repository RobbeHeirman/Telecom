//
// Created by robbe on 29/12/18.
//

#ifndef TELECOM_RSVPELEMENT_H
#define TELECOM_RSVPELEMENT_H

#include <click/element.hh>
#include <click/vector.hh>
#include "RSVPStructs.hh"


CLICK_DECLS

/**
 * @class
 * Abstract class for RSVPElements
 */
class RSVPElement: public Element {

public:
    RSVPElement() = default;
    ~RSVPElement() = default;

protected:
    /**
     * Helper function that will help us find package ptrs.
     * @param: Packet is a ptr to package where we want to extract the path ptrs.
     */
    void find_path_ptrs(Packet*& p, RSVPSession*& session, RSVPHop*& hop, RSVPSenderTemplate* sender,
                        RSVPSenderTSpec* tspec, Vector<RSVPPolicyData*>& policy_data);

};

CLICK_ENDDECLS

#endif //TELECOM_RSVPELEMENT_H
