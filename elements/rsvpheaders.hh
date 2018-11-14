
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
    uint8_t     _;          // 5
    uint16_t    length;     // 6 - 7
};

#define RSVP_VERSION        0x1

enum RSVPType : uint8_t {
    PATH        = 0x01,
    RESV        = 0x02,
    PATHERR     = 0x03,
    RESVERR     = 0x04,
    PATHTEAR    = 0x05,
    RESVTEAR    = 0x06,
    RESVCONF    = 0x07
};

/*------------+-------------+-------------+-------------+
|       Length (bytes)      |  Class-Num  |   C-Type    |
+-------------+-------------+-------------+------------*/
struct RSVPObject
{
    uint16_t    length;     // 0 - 1
    uint8_t     class_num;  // 2
    uint8_t     c_type;     // 3
};

enum RSVPClass : uint8_t {
    SESSION         = 0x01,
    HOP             = 0x03,
    INTEGRITY       = 0x04,
    TIME_VALUES     = 0x05,
    ERROR_SPEC      = 0x06,
    SCOPE           = 0x07,
    STYLE           = 0x08,
    FLOWSPEC        = 0x09,
    FILTERSPEC      = 0x0a,
    SENDER_TEMPLATE = 0x0b,
    SENDER_TSPEC    = 0x0c,
    POLICY_DATA     = 0x0e,
    RESV_CONFIRM    = 0x0f
};

/*------------+-------------+-------------+-------------+
|             IPv4 DestAddress (4 bytes)                |
+-------------+-------------+-------------+-------------+
| Protocol Id |    Flags    |          DstPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSession : public RSVPObject
{
    uint32_t    dest_addr;  // 0 - 3
    uint8_t     proto;      // 4
    uint8_t     flags;      // 5
    uint16_t    dest_port;  // 6 - 7
};

enum RSVPSessionFlags : uint8_t {
    NONE    = 0x00,
    EPOLICE = 0x01
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

#define RSVP_ERR_FLAG_INPLACE   0x01
#define RSVP_ERR_FLAG_NOTGUILTY 0x02

/*------------+-------------+-------------+-------------+
|                IPv4 Src Address (4 bytes)             |
+-------------+-------------+-------------+-------------+
//                                                      //
+-------------+-------------+-------------+-------------+
|                IPv4 Src Address (4 bytes)             |
+-------------+-------------+-------------+------------*/
struct RSVPScope : public RSVPObject
{
    // Variable number of addresses...
};

/*------------+-------------+-------------+-------------+
|   Flags     |              Option Vector              |
+-------------+-------------+-------------+------------*/
struct RSVPStyle : public RSVPObject
{
    uint8_t     flags;          // 0
    uint32_t    options : 24;   // 1 - 3
};

/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   V   |    Unused             |     OVERALL LENGTH            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
struct RSVPIntServHeader : public RSVPObject
{
    uint8_t     version : 4;    // 0
    uint16_t    _       : 12;   //   - 1
    uint16_t    o_length;       // 2 - 3
};

/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  SVC_NUMBER   |B| Reserved    |            SVC_LENGTH         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
struct RSVPPerServiceHeader
{
    uint8_t     service_nr;     // 0
    uint8_t     break_b : 1;    // 1
    uint8_t     _ : 7;
    uint16_t    length;         // 2 - 3
};

/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  PARAM_NUM    |I   FLAGS      |         PARAM_LENGTH          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
struct RSVPServiceParamHeader
{
    uint8_t     param_nr;   // 0
    uint8_t     flags;      // 1
    uint16_t    length;     // 2 - 3
};

/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    5  (c)     |0| reserved    |             6 (d)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   127 (e)     |    0 (f)      |             5 (g)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Token Bucket Rate [r] (32-bit IEEE floating point number)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Token Bucket Size [b] (32-bit IEEE floating point number)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Peak Data Rate [p] (32-bit IEEE floating point number)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Minimum Policed Unit [m] (32-bit integer)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Maximum Packet Size [M]  (32-bit integer)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
struct RSVPFlowspec : public RSVPIntServHeader
{
    RSVPPerServiceHeader    service_header; // 0  - 3
    RSVPServiceParamHeader  param_header;   // 4  - 7
    uint32_t                r;              // 8  - 11
    float                   b;              // 12 - 15
    float                   p;              // 16 - 19
    uint32_t                m;              // 20 - 23
    uint32_t                M;              // 24 - 27
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

/*+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| 0 (a) |    reserved           |             7 (b)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    1  (c)     |0| reserved    |             6 (d)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   127 (e)     |    0 (f)      |             5 (g)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Token Bucket Rate [r] (32-bit IEEE floating point number)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Token Bucket Size [b] (32-bit IEEE floating point number)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Peak Data Rate [p] (32-bit IEEE floating point number)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Minimum Policed Unit [m] (32-bit integer)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Maximum Packet Size [M]  (32-bit integer)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+*/
struct RSVPSenderTspec : public RSVPIntServHeader
{
    RSVPPerServiceHeader    service_header; // 0  - 3
    RSVPServiceParamHeader  param_header;   // 4  - 7
    float                   r;              // 8  - 11
    float                   b;              // 12 - 15
    float                   p;              // 16 - 19
    uint32_t                m;              // 20 - 23
    uint32_t                M;              // 24 - 27
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
