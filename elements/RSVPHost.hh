
#ifndef CLICK_RSVPHOST_HH
#define CLICK_RSVPHOST_HH

#include <string.h>
#include <click/error.hh>
#include <click/element.hh>

CLICK_DECLS

class RSVPHost: public Element
{
public:

    // The constructor and destructor
    RSVPHost();
    ~RSVPHost();

    // Standard click information functions
    const char* class_name() const { return "RSVPHost"; }
    const char* port_count() const { return "0/1"; }
    const char* processing() const { return PUSH; }

    // Standard click functions
    int configure(Vector<String>&, ErrorHandler*);
    void push(int, Packet*);

    // Handler functions
    /// session ID <int>, DST <addr>, PORT <port>
    static int session(const String&, Element*, void*, ErrorHandler*);
    /// sender ID <int>, SRC <addr>, PORT <port>
    static int sender(const String&, Element*, void*, ErrorHandler*);
    /// reserve ID <int>, CONF <int?>
    static int reserve(const String&, Element*, void*, ErrorHandler*);
    /// release ID <int>
    static int release(const String&, Element*, void*, ErrorHandler*);
    void add_handlers();
};

CLICK_ENDDECLS

#endif //CLICK_RSVPHOST_HH
