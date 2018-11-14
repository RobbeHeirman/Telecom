
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
    #define RSVPVersion 0x1
    enum Type : uint8_t {
        Path        = 0x01,
        Resv        = 0x02,
        PathErr     = 0x03,
        ResvErr     = 0x04,
        PathTear    = 0x05,
        ResvTear    = 0x06,
        ResvConf    = 0x07
    };

#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    unsigned   version : 4; // 0
    unsigned   flags   : 4; //   - 0
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    unsigned   flags   : 4; // 0
    unsigned   version : 4; //   - 0
#else
#   error "unknown byte order"
#endif
    Type        msg_type;   // 1
    uint16_t    checksum;   // 2 - 3
    uint8_t     send_ttl;   // 4
    uint8_t     _;          // 5
    uint16_t    length;     // 6 - 7


    static unsigned char* write(unsigned char* const packet,
                                RSVPHeader::Type const message_type,
                                uint8_t const send_ttl) {

        auto* const header {(RSVPHeader*) packet};
        header->version     = RSVPVersion;
        header->msg_type    = message_type;
        header->send_ttl    = send_ttl;
        return packet + sizeof(RSVPHeader);
    }
};


/*------------+-------------+-------------+-------------+
|       Length (bytes)      |  Class-Num  |   C-Type    |
+-------------+-------------+-------------+------------*/
struct RSVPObject
{
    enum Class : uint8_t {
        Session         = 0x01,
        Hop             = 0x03,
        Integrity       = 0x04,
        TimeValues      = 0x05,
        ErrorSpec       = 0x06,
        Scope           = 0x07,
        Style           = 0x08,
        FlowSpec        = 0x09,
        FilterSpec      = 0x0a,
        SenderTemplate  = 0x0b,
        SenderTSpec     = 0x0c,
        PolicyData      = 0x0e,
        ResvConfirm     = 0x0f
    };

    uint16_t    length;     // 0 - 1
    Class       class_num;  // 2
    uint8_t     c_type;     // 3
};


/*------------+-------------+-------------+-------------+
|             IPv4 DestAddress (4 bytes)                |
+-------------+-------------+-------------+-------------+
| Protocol Id |    Flags    |          DstPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSession : public RSVPObject
{
    enum Flags : uint8_t {
        None    = 0x00,
        EPolice = 0x01
    };

    uint32_t    dest_addr;  // 0 - 3
    uint8_t     proto;      // 4
    Flags       flags;      // 5
    uint16_t    dest_port;  // 6 - 7


    static unsigned char* write(unsigned char* const packet,
                                uint32_t const destination_address,
                                uint8_t  const proto,
                                uint16_t const destination_port,
                                Flags const flags = Flags::None) {

        auto* const session {(RSVPSession*) packet};
        session->length     = htons(sizeof(RSVPSession));
        session->class_num  = RSVPObject::Session;
        session->c_type     = 0x01;
        session->dest_addr  = htonl(destination_address);
        session->proto      = proto;
        session->flags      = flags;
        session->dest_port  = htons(destination_port);
        return packet + sizeof(RSVPSession);
    }
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


    static unsigned char* write(unsigned char* const packet,
                                uint32_t const address,
                                uint32_t const lih = 0) {

        auto* const hop {(RSVPHop*) packet};
        hop->length     = htons(sizeof(RSVPHop));
        hop->class_num  = RSVPObject::Hop;
        hop->c_type     = 0x01;
        hop->address    = htonl(address);
        hop->lih        = htonl(lih);
        return packet + sizeof(RSVPHop);
    }
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


    static unsigned char* write(unsigned char* const packet,
                                uint32_t const refresh) {

        auto* const time_values {(RSVPTimeValues*) packet};
        time_values->length     = htons(sizeof(RSVPTimeValues));
        time_values->class_num  = RSVPObject::TimeValues;
        time_values->c_type     = 0x01;
        time_values->refresh    = htonl(refresh);
        return packet + sizeof(RSVPTimeValues);
    }
};


/*------------+-------------+-------------+-------------+
|            IPv4 Error Node Address (4 bytes)          |
+-------------+-------------+-------------+-------------+
|    Flags    |  Error Code |        Error Value        |
+-------------+-------------+-------------+------------*/
struct RSVPErrorSpec : public RSVPObject
{
    #define RSVPErrorInPlace    0x01
    #define RSVPErrorNotGuilty  0x02

    uint32_t    address;    // 0 - 3
    uint8_t     flags;      // 4
    uint8_t     err_code;   // 5
    uint16_t    err_value;  // 6 - 7
};


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


    static unsigned char* write(unsigned char* const packet,
                                uint32_t const source_address,
                                uint16_t const source_port) {

        auto* const s_template {(RSVPSenderTemplate*) packet};
        s_template->length      = htons(sizeof(RSVPSenderTemplate));
        s_template->class_num   = RSVPObject::SenderTemplate;
        s_template->c_type      = 0x01;
        s_template->src_addr    = htonl(source_address);
        s_template->src_port    = htons(source_port);
        return packet + sizeof(RSVPSenderTemplate);
    }
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
struct RSVPSenderTSpec : public RSVPIntServHeader
{
    RSVPPerServiceHeader    service_header; // 0  - 3
    RSVPServiceParamHeader  param_header;   // 4  - 7
    float                   r;              // 8  - 11
    float                   b;              // 12 - 15
    float                   p;              // 16 - 19
    uint32_t                m;              // 20 - 23
    uint32_t                M;              // 24 - 27


    static unsigned char* write(unsigned char* const packet,
                                float const          r,
                                float const          b,
                                float const          p,
                                uint32_t const       m,
                                uint32_t const       M) {

        auto* const s_tspec {(RSVPSenderTSpec*) packet};
        s_tspec->length                     = htons(sizeof(RSVPSenderTSpec));
        s_tspec->class_num                  = RSVPObject::SenderTSpec;
        s_tspec->c_type                     = 0x02;
        s_tspec->version                    = 0x0;
        s_tspec->o_length                   = htons(0x0007);
        s_tspec->service_header.service_nr  = 0x01;
        s_tspec->service_header.length      = htons(0x0006);
        s_tspec->param_header.param_nr      = 0x7f;
        s_tspec->param_header.length        = htons(0x0005);

        uint32_t const temp_r {htonl(*(uint32_t*)&r)};
        uint32_t const temp_b {htonl(*(uint32_t*)&b)};
        uint32_t const temp_p {htonl(*(uint32_t*)&p)};
        s_tspec->r                          = *(float*)&temp_r;
        s_tspec->b                          = *(float*)&temp_b;
        s_tspec->p                          = *(float*)&temp_p;

        s_tspec->m                          = htonl(m);
        s_tspec->M                          = htonl(M);
        return packet + sizeof(RSVPSenderTSpec);
    }
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
