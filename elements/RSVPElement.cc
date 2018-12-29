#include <click/config.h>
#include "RSVPElement.hh"
#include <click/glue.hh>
#include <arpa/inet.h>


CLICK_DECLS

void RSVPElement::find_path_ptrs(Packet*& p, RSVPSession*& session, RSVPHop*& hop, RSVPSenderTemplate*& sender,
                    RSVPSenderTSpec*& tspec, Vector<RSVPPolicyData*>& policy_data){

    // Main object to iterate over our package objects
    RSVPHeader* header = (RSVPHeader*) p->data();
    RSVPObject* object = (RSVPObject*) (header + 1 ) ; // Ptr to the RSVPObject package

    while((const unsigned  char*)object < p->end_data()){
        // We want to handle on the type of object gets trough
        switch (object->class_num){
            case RSVPObject::Integrity: {
                click_chatter("INTEGRITY is ignored");
                auto integrity = (RSVPIntegrity*) (object);
                object = (RSVPObject*) (integrity + 1);
                break;
            }
            case RSVPObject::Class::Session : {
                if(session != 0){click_chatter("More then one session object");} // TODO: error msg?
                session = (RSVPSession*) object; // Downcast to RSVPSession object
                object = (RSVPObject*) (session + 1);
                break;
            }
            case RSVPObject::Class::Hop : {
                if(hop != 0){click_chatter("More then one hop element");}
                hop = (RSVPHop *) object; // We downcast to our RSVPHOP object
                object = (RSVPObject*)( hop + 1);
                break;
            }

            case RSVPObject::Class::TimeValues : {
                auto* time = (RSVPTimeValues*) object;
                object = (RSVPObject*) (time + 1);
                break;
            }
            case RSVPObject::Class ::PolicyData : {
                RSVPPolicyData* p_data = (RSVPPolicyData*) object;
                policy_data.push_back(p_data);
                object = (RSVPObject*) (p_data + 1);
                break;
            }
            case RSVPObject::Class::SenderTemplate : {
                if(sender != 0){click_chatter("More the one sender template");}
                sender = (RSVPSenderTemplate*) object;
                object = (RSVPObject*) (sender + 1);
                break;
            }
            case RSVPObject::Class::SenderTSpec : {
                tspec = (RSVPSenderTSpec*) object;
                object = (RSVPObject*) (tspec + 1);
                break;
            }
            default:
                click_chatter("SHOULDN't HAPPEN!");
                object = (RSVPObject*) (object + 1);
                break;
        }
    }

    if (check(not session, "RSVPHost received Path message without session object")) return;
    if (check(not hop, "RSVPHost received Path message without hop object")) return;
    if (check(not time, "RSVPHost received Path message without time values object")) return;
    if (check(not sender, "RSVPHost received Path message without SenderTemplate object")) return;
    if (check(not tspec, "RSVPHost received Path message without tspec object")) return;
}

bool RSVPElement::check(const bool condition, const String& message) {

    if (condition) {
        ErrorHandler::default_handler()->error(message.c_str());
    }
    return condition;
}

CLICK_ENDDECLS

EXPORT_ELEMENT(RSVPElement)