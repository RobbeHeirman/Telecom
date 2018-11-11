
#ifndef CLICK_RSVPMESSAGE_HH
#define CLICK_RSVPMESSAGE_HH

#include <click/glue.hh>
#include <click/integers.hh>

CLICK_DECLS

/*     0             1             2             3
+-------------+-------------+-------------+-------------+
| Vers | Flags|  Msg Type   |       RSVP Checksum       |
+-------------+-------------+-------------+-------------+
|  Send_TTL   | (Reserved)  |        RSVP Length        |
+-------------+-------------+-------------+-------------+ */
struct RSVPHeader
{
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    unsigned   version : 4; // 0
    unsigned   flags   : 4;
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    unsigned   flags   : 4; // 0
    unsigned   version : 4;
#else
#   error "unknown byte order"
#endif
    uint8_t     msg_type;   // 1
    uint16_t    checksum;   // 2 - 3
    uint8_t     send_ttl;   // 4
    uint8_t     reserved;   // 5
    uint16_t    length;     // 6 - 7
};

#define RSVP_VERSION        1

#define RSVP_TYPE_PATH      1
#define RSVP_TYPE_RESV      2
#define RSVP_TYPE_PATHERR   3
#define RSVP_TYPE_RESVERR   4
#define RSVP_TYPE_PATHTEAR  5
#define RSVP_TYPE_RESVTEAR  6
#define RSVP_TYPE_RESVCONF  7

/*     0             1             2             3
+-------------+-------------+-------------+-------------+
|       Length (bytes)      |  Class-Num  |   C-Type    |
+-------------+-------------+-------------+-------------+
|                                                       |
//                  (Object contents)                   //
|                                                       |
+-------------+-------------+-------------+-------------+ */
struct RSVPObjectHeader
{
    uint16_t    length;    // 0 - 1
    uint8_t     class_num; // 2
    uint8_t     c_type;    // 3
};

CLICK_ENDDECLS

#endif // CLICK_RSVPMESSAGE_HH
