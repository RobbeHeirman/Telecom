
#ifndef CLICK_RSVPMESSAGE_HH
#define CLICK_RSVPMESSAGE_HH

#include <click/glue.hh>
#include <click/integers.hh>

CLICK_DECLS

/*------------+-------------+-------------+-------------+
| Vers | Flags|  Msg Type   |       RSVP Checksum       |
+-------------+-------------+-------------+-------------+
|  Send_TTL   | (Reserved)  |        RSVP Length        |
+-------------+-------------+-------------+------------*/
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

/*------------+-------------+-------------+-------------+
|       Length (bytes)      |  Class-Num  |   C-Type    |
+-------------+-------------+-------------+------------*/
struct RSVPObject
{
    uint16_t    length;     // 0 - 1
    uint8_t     class_num;  // 2
    uint8_t     c_type;     // 3
};

/*------------+-------------+-------------+-------------+
|             IPv4 DestAddress (4 bytes)                |
+-------------+-------------+-------------+-------------+
| Protocol Id |    Flags    |          DstPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSession
{
    in_addr     dest_addr;  // 0 - 3
    uint8_t     protocol;   // 4
    uint8_t     flags;      // 5
    uint16_t    dest_port;  // 6 - 7
};

/*------------+-------------+-------------+-------------+
|             IPv4 Next/Previous Hop Address            |
+-------------+-------------+-------------+-------------+
|                 Logical Interface Handle              |
+-------------+-------------+-------------+------------*/
struct RSVPHop
{
    in_addr     address;    // 0 - 3
    uint32_t    lih;        // 4 - 7
};

/**/
struct RSVPIntegrity
{
};

/*------------+-------------+-------------+-------------+
|                   Refresh Period R                    |
+-------------+-------------+-------------+------------*/
struct RSVPTimeValues
{
    uint32_t    refresh;    // 0 - 3
};

/*------------+-------------+-------------+-------------+
|            IPv4 Error Node Address (4 bytes)          |
+-------------+-------------+-------------+-------------+
|    Flags    |  Error Code |        Error Value        |
+-------------+-------------+-------------+------------*/
struct RSVPErrorSpec
{
    in_addr     address;    // 0 - 3
    uint8_t     flags;      // 4
    uint8_t     err_code;   // 5
    uint16_t    err_value;  // 6 - 7
};

#define RSVP_ERROR_INPLACE      1
#define RSVP_ERROR_NOTGUILTY    2

/*------------+-------------+-------------+-------------+
|                IPv4 Src Address (4 bytes)             |
+-------------+-------------+-------------+-------------+
//                                                      //
+-------------+-------------+-------------+-------------+
|                IPv4 Src Address (4 bytes)             |
+-------------+-------------+-------------+------------*/
struct RSVPScopeAddress
{
    // Variable number of addresses...
};

/*------------+-------------+-------------+-------------+
|   Flags     |              Option Vector              |
+-------------+-------------+-------------+------------*/
struct RSVPStyle
{
    uint8_t     flags;      // 0
    uint32_t    options:24; // 1 - 3
};

/* RFC 2210 */
struct RSVPFlowspec
{
};

/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPFilterSpec
{
    in_addr     src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7
};

/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSenderTemplate
{
    in_addr     src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7
};

/**/
struct RSVPSenderTspec
{
};

/**/
struct RSVPPolicyData
{
};

/*------------+-------------+-------------+-------------+
|            IPv4 Receiver Address (4 bytes)            |
+-------------+-------------+-------------+------------*/
struct RSVPResvConfirm
{
    in_addr     rec_addr;   // 0 - 3
};

CLICK_ENDDECLS

#endif // CLICK_RSVPMESSAGE_HH
