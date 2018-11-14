
#ifndef CLICK_RSVPSOURCE_HH
#define CLICK_RSVPSOURCE_HH

#include "rsvp_structs.hh"
#include <string.h>
#include <click/error.hh>
#include <click/element.hh>

CLICK_DECLS

class RSVPSource: public Element
{
public:
    RSVPSource();
    ~RSVPSource();

    const char* class_name() const { return "RSVPSource"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return PULL; }

    Packet* pull(int);

    static int send(const String&, Element*, void*, ErrorHandler*);
    void add_handlers();

private:
    bool m_send;
};

CLICK_ENDDECLS

#endif // CLICK_RSVPSOURCE_HH
