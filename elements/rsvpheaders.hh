
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

#define RSVP_CLASS_SESSION          1
#define RSVP_CLASS_RSVPHOP          3
#define RSVP_CLASS_INTEGRITY        4
#define RSVP_CLASS_TIME_VALUES      5
#define RSVP_CLASS_ERROR_SPEC       6
#define RSVP_CLASS_SCOPE            7
#define RSVP_CLASS_STYLE            8
#define RSVP_CLASS_FLOWSPEC         9
#define RSVP_CLASS_FILTER_SPEC      10
#define RSVP_CLASS_SENDER_TEMPLATE  11
#define RSVP_CLASS_SENDER_TSPEC     12
#define RSVP_CLASS_POLICY_DATA      14
#define RSVP_CLASS_RESV_CONFIRM     15

/*------------+-------------+-------------+-------------+
|             IPv4 DestAddress (4 bytes)                |
+-------------+-------------+-------------+-------------+
| Protocol Id |    Flags    |          DstPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSession : public RSVPObject
{
    uint32_t    dest_addr;  // 0 - 3
    uint8_t     protocol;   // 4
    uint8_t     flags;      // 5
    uint16_t    dest_port;  // 6 - 7
};

/*------------+-------------+-------------+-------------+
|             IPv4 Next/Previous Hop Address            |
+-------------+-------------+-------------+-------------+
|                 Logical Interface Handle              |
+-------------+-------------+-------------+------------*/
struct RSVPHop : public RSVPObject
{
    uint32_t    address;    // 0 - 3
    uint32_t    lih;        // 4 - 7
};

/**/
struct RSVPIntegrity : public RSVPObject
{
};

/*------------+-------------+-------------+-------------+
|                   Refresh Period R                    |
+-------------+-------------+-------------+------------*/
struct RSVPTimeValues : public RSVPObject
{
    uint32_t    refresh;    // 0 - 3
};

/*------------+-------------+-------------+-------------+
|            IPv4 Error Node Address (4 bytes)          |
+-------------+-------------+-------------+-------------+
|    Flags    |  Error Code |        Error Value        |
+-------------+-------------+-------------+------------*/
struct RSVPErrorSpec : public RSVPObject
{
    uint32_t    address;    // 0 - 3
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
struct RSVPScopeAddress : public RSVPObject
{
    // Variable number of addresses...
};

/*------------+-------------+-------------+-------------+
|   Flags     |              Option Vector              |
+-------------+-------------+-------------+------------*/
struct RSVPStyle : public RSVPObject
{
    uint8_t     flags;      // 0
    uint32_t    options:24; // 1 - 3
};

/* RFC 2210 */
struct RSVPFlowspec : public RSVPObject
{
};

/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPFilterSpec : public RSVPObject
{
    uint32_t    src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7
};

/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSenderTemplate : public RSVPObject
{
    uint32_t    src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7
};

/**/
struct RSVPSenderTspec : public RSVPObject
{
};

/**/
struct RSVPPolicyData : public RSVPObject
{
};

/*------------+-------------+-------------+-------------+
|            IPv4 Receiver Address (4 bytes)            |
+-------------+-------------+-------------+------------*/
struct RSVPResvConfirm : public RSVPObject
{
    uint32_t    rec_addr;   // 0 - 3
};

CLICK_ENDDECLS

#endif // CLICK_RSVPMESSAGE_HH
