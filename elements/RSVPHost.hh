
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include <string.h>
#include <click/error.hh>
#include <click/element.hh>

CLICK_DECLS

class RSVPHost: public Element
{
public:
    /// The constructor and destructor.
    RSVPHost();
    ~RSVPHost();

    /// Basic click element functions.
    const char* class_name() const { return "RSVPHost"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return AGNOSTIC; }

    /// The push and pull functions.
    void push(int, Packet*);
    Packet* pull(int);

    /// Handler functions.
    static int session(const String&, Element*, void*, ErrorHandler*);
    static int sender(const String&, Element*, void*, ErrorHandler*);
    static int reserve(const String&, Element*, void*, ErrorHandler*);
    static int release(const String&, Element*, void*, ErrorHandler*);
    void add_handlers();
};

CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH
