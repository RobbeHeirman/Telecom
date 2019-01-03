
#pragma GCC diagnostic ignored "-Wstrict-aliasing"

#ifndef CLICK_RSVPMESSAGE_HH
#define CLICK_RSVPMESSAGE_HH

#include <sys/types.h>
#include <click/glue.hh>
#include <click/element.hh>
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


    static void write(unsigned char*& packet,
                      const RSVPHeader::Type message_type,
                      const uint8_t send_ttl = 250) {

        const auto header {(RSVPHeader*) packet};
        header->version     = RSVPVersion;
        header->msg_type    = message_type;
        header->send_ttl    = send_ttl;
        packet += sizeof(RSVPHeader);
    }

    static void complete(WritablePacket *const packet,
                         const uint16_t length) {

        const auto header {(RSVPHeader*) packet->data()};
        header->length = htons(length);
        header->checksum = 0;
        header->checksum = click_in_cksum(packet->data(), length);
    }
};


/*------------+-------------+-------------+-------------+
|       Length (bytes)      |  Class-Num  |   C-Type    |
+-------------+-------------+-------------+------------*/
struct RSVPObject
{
    enum Class : uint8_t {
        Null            = 0x00,
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

    in_addr     dest_addr;  // 0 - 3
    uint8_t     proto;      // 4
    Flags       flags;      // 5
    uint16_t    dest_port;  // 6 - 7


    static void write(unsigned char*& packet,
                      const in_addr destination_address,
                      const uint8_t proto,
                      const uint16_t destination_port,
                      const Flags flags = Flags::None) {

        const auto session {(RSVPSession*) packet};
        session->length     = htons(sizeof(RSVPSession));
        session->class_num  = RSVPObject::Session;
        session->c_type     = 0x01;
        session->dest_addr  = destination_address;
        session->proto      = proto;
        session->flags      = flags;
        session->dest_port  = htons(destination_port);
        packet += sizeof(RSVPSession);
    }
};


/*------------+-------------+-------------+-------------+
|             IPv4 Next/Previous Hop Address            |
+-------------+-------------+-------------+-------------+
|                 Logical Interface Handle              |
+-------------+-------------+-------------+------------*/
struct RSVPHop : public RSVPObject
{
    in_addr     address;    // 0 - 3
    uint32_t    lih;        // 4 - 7


    static void write(unsigned char*& packet,
                      const in_addr address,
                      const uint32_t lih = 0) {

        const auto hop {(RSVPHop*) packet};
        hop->length     = htons(sizeof(RSVPHop));
        hop->class_num  = RSVPObject::Hop;
        hop->c_type     = 0x01;
        hop->address    = address;
        hop->lih        = htonl(lih);
        packet += sizeof(RSVPHop);
    }
};


/**/
struct RSVPIntegrity : public RSVPObject
{
    static void write(unsigned char*& packet) {

        const auto integrity {(RSVPIntegrity*) packet};
        integrity->length = htons(sizeof(RSVPIntegrity));
        integrity->class_num = RSVPObject::Integrity;
        integrity->c_type = 0x01;
        packet += sizeof(RSVPIntegrity);
    }
};


/*------------+-------------+-------------+-------------+
|                   Refresh Period R                    |
+-------------+-------------+-------------+------------*/
struct RSVPTimeValues : public RSVPObject
{
    uint32_t    refresh;    // 0 - 3


    static void write(unsigned char*& packet,
                      const uint32_t refresh) {

        const auto time_values {(RSVPTimeValues*) packet};
        time_values->length     = htons(sizeof(RSVPTimeValues));
        time_values->class_num  = RSVPObject::TimeValues;
        time_values->c_type     = 0x01;
        time_values->refresh    = htonl(refresh);
        packet += sizeof(RSVPTimeValues);
    }
};


/*------------+-------------+-------------+-------------+
|            IPv4 Error Node Address (4 bytes)          |
+-------------+-------------+-------------+-------------+
|    Flags    |  Error Code |        Error Value        |
+-------------+-------------+-------------+------------*/
struct RSVPErrorSpec : public RSVPObject
{
    enum Flags : uint8_t {
        InPlace     = 0x01,
        NotGuilty   = 0x02
    };

    enum ErrorCode : uint8_t {
        Confirmation        = 0,
        UnkownResvStyle     = 6,
        UnknownObjectClass  = 13,
        UnknownCType        = 14,
        API                 = 20,
        TrafficControlError = 21,
        RSVPSystemError     = 23
    };

    in_addr     address;    // 0 - 3
    uint8_t     flags;      // 4
    ErrorCode   err_code;   // 5
    uint16_t    err_value;  // 6 - 7


    static void write(unsigned char*& packet,
                      const in_addr address,
                      const uint8_t flags,
                      const ErrorCode err_code = Confirmation,
                      const uint16_t err_value = 0x0000) {

        const auto error_spec {(RSVPErrorSpec*) packet};
        error_spec->length      = htons(sizeof(RSVPErrorSpec));
        error_spec->class_num   = RSVPObject::ErrorSpec;
        error_spec->c_type      = 0x01;
        error_spec->address     = address;
        error_spec->flags       = flags;
        error_spec->err_code    = err_code;
        error_spec->err_value   = htons(err_value);
        packet += sizeof(RSVPErrorSpec);
    }
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
    // TODO
    
    
    static void write(unsigned char*& packet) {
        
        const auto scope {(RSVPScope*) packet};
        scope->length       = htons(sizeof(RSVPScope));
        scope->class_num    = RSVPObject::Scope;
        scope->c_type       = 1;
        packet += sizeof(RSVPScope);
    }
};


/*------------+-------------+-------------+-------------+
|   Flags     |              Option Vector              |
+-------------+-------------+-------------+------------*/
struct RSVPStyle : public RSVPObject
{
    uint32_t    _ : 24;             // 0 - 2
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
    uint8_t     __ : 3;             // 3
    uint8_t     sharing : 2;        //   - 3
    uint8_t     s_selection : 3;    //   - 3
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
    uint8_t     s_selection : 3;    // 3
    uint8_t     sharing : 2;        //   - 3
    uint8_t     __ : 3;             //   - 3
#else
#   error "unknown byte order"
#endif
    static void write(unsigned char*& packet,
                      const uint8_t sharing = 0b01,
                      const uint8_t sender_selection = 0b010) {

        auto style {(RSVPStyle*) packet};
        style->length       = htons(sizeof(RSVPStyle));
        style->class_num    = RSVPObject::Style;
        style->c_type       = 0x01;
        style->sharing      = sharing;
        style->s_selection  = sender_selection;
        packet += sizeof(RSVPStyle);
    }
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
struct RSVPFlowSpec : public RSVPIntServHeader
{
    RSVPPerServiceHeader    service_header; // 0  - 3
    RSVPServiceParamHeader  param_header;   // 4  - 7
    float                   r;              // 8  - 11 bucket rate
    float                   b;              // 12 - 15 bucket size
    float                   p;              // 16 - 19 peak data rate
    uint32_t                m;              // 20 - 23 minimum policed unit
    uint32_t                M;              // 24 - 27 maximum packet size
    
    
    static void write(unsigned char*& packet,
                      float const r,
                      float const b,
                      float const p,
                      const uint32_t m,
                      const uint32_t M) {

        const auto flow_spec {(RSVPFlowSpec*) packet};
        flow_spec->length                     = htons(sizeof(RSVPFlowSpec));
        flow_spec->class_num                  = RSVPObject::FlowSpec;
        flow_spec->c_type                     = 0x02;
        flow_spec->version                    = 0x0;
        flow_spec->o_length                   = htons(0x0007);
        flow_spec->service_header.service_nr  = 0x01;
        flow_spec->service_header.length      = htons(0x0006);
        flow_spec->param_header.param_nr      = 0x7f;
        flow_spec->param_header.length        = htons(0x0005);

        const uint32_t temp_r {htonl(*(uint32_t*)&r)};
        const uint32_t temp_b {htonl(*(uint32_t*)&b)};
        const uint32_t temp_p {htonl(*(uint32_t*)&p)};
        flow_spec->r                          = *(float*)&temp_r;
        flow_spec->b                          = *(float*)&temp_b;
        flow_spec->p                          = *(float*)&temp_p;

        flow_spec->m                          = htonl(m);
        flow_spec->M                          = htonl(M);
        packet += sizeof(RSVPFlowSpec);
    }
};


/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPFilterSpec : public RSVPObject
{
    in_addr     src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7


    static void write(unsigned char*& packet,
                      const in_addr source_address,
                      const uint16_t source_port) {

        const auto filter_spec {(RSVPFilterSpec*) packet};
        filter_spec->length     = htons(sizeof(RSVPFilterSpec));
        filter_spec->class_num  = RSVPObject::FilterSpec;
        filter_spec->c_type     = 0x01;
        filter_spec->src_addr   = source_address;
        filter_spec->src_port   = htons(source_port);
        packet += sizeof(RSVPFilterSpec);
    }

};


/*------------+-------------+-------------+-------------+
|               IPv4 SrcAddress (4 bytes)               |
+-------------+-------------+-------------+-------------+
|    //////   |    //////   |          SrcPort          |
+-------------+-------------+-------------+------------*/
struct RSVPSenderTemplate : public RSVPObject
{
    in_addr     src_addr;   // 0 - 3
    uint16_t    _; // (unused) 4 - 5
    uint16_t    src_port;   // 6 - 7


    static void write(unsigned char*& packet,
                      const in_addr source_address,
                      const uint16_t source_port) {

        const auto s_template {(RSVPSenderTemplate*) packet};
        s_template->length      = htons(sizeof(RSVPSenderTemplate));
        s_template->class_num   = RSVPObject::SenderTemplate;
        s_template->c_type      = 0x01;
        s_template->src_addr    = source_address;
        s_template->src_port    = htons(source_port);
        packet += sizeof(RSVPSenderTemplate);
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


    static void write(unsigned char*& packet,
                      float const          r,
                      float const          b,
                      float const          p,
                      const uint32_t       m,
                      const uint32_t       M) {

        const auto s_tspec {(RSVPSenderTSpec*) packet};
        s_tspec->length                     = htons(sizeof(RSVPSenderTSpec));
        s_tspec->class_num                  = RSVPObject::SenderTSpec;
        s_tspec->c_type                     = 0x02;
        s_tspec->version                    = 0x0;
        s_tspec->o_length                   = htons(0x0007);
        s_tspec->service_header.service_nr  = 0x01;
        s_tspec->service_header.length      = htons(0x0006);
        s_tspec->param_header.param_nr      = 0x7f;
        s_tspec->param_header.length        = htons(0x0005);

        const uint32_t temp_r {htonl(*(uint32_t*)&r)};
        const uint32_t temp_b {htonl(*(uint32_t*)&b)};
        const uint32_t temp_p {htonl(*(uint32_t*)&p)};
        s_tspec->r                          = *(float*)&temp_r;
        s_tspec->b                          = *(float*)&temp_b;
        s_tspec->p                          = *(float*)&temp_p;

        s_tspec->m                          = htonl(m);
        s_tspec->M                          = htonl(M);
        packet += sizeof(RSVPSenderTSpec);
    }
};


/**/
struct RSVPPolicyData : public RSVPObject
{
    static void write(unsigned char*& packet) {

        const auto policy_data {(RSVPPolicyData*) packet};
        policy_data->length     = htons(sizeof(RSVPPolicyData));
        policy_data->class_num  = RSVPObject::PolicyData;
        policy_data->c_type     = 0x01;
        packet += sizeof(RSVPPolicyData);
    }
};


/*------------+-------------+-------------+-------------+
|            IPv4 Receiver Address (4 bytes)            |
+-------------+-------------+-------------+------------*/
struct RSVPResvConfirm : public RSVPObject
{
    in_addr     rec_addr;   // 0 - 3


    static void write(unsigned char*& packet,
                      const in_addr receiving_address) {

        const auto resv_confirm {(RSVPResvConfirm*) packet};
        resv_confirm->length    = htons(sizeof(RSVPResvConfirm));
        resv_confirm->class_num = RSVPObject::ResvConfirm;
        resv_confirm->c_type    = 0x01;
        resv_confirm->rec_addr  = receiving_address;
        packet += sizeof(RSVPResvConfirm);
    }
};


/**
 * Struct to store a(n FF-style) flow descriptor consisting of a FlowSpec and a FilterSpec object
 */
struct FlowDescriptor
{
    RSVPFlowSpec* flow_spec;
    RSVPFilterSpec* filter_spec;
};


/**
 * Struct to store a (FF) sender descriptor consisting of a SenderTemplate and a SenderTSpec object
 */
struct SenderDescriptor
{
    RSVPSenderTemplate* sender;
    RSVPSenderTSpec* tspec;
};


/**
 * Struct to store pointers to the objects of a PATH message
 */
struct Path
{
    RSVPSession*            session                 {nullptr};
    RSVPHop*                hop                     {nullptr};
    RSVPTimeValues*         time_values             {nullptr};
    Vector<RSVPPolicyData*> policy_data             {};
    SenderDescriptor        sender                  {nullptr, nullptr};
};


/**
 * Struct to store pointers to the objects of a RESV message
 */
struct Resv
{
    RSVPSession*            session                 {nullptr};
    RSVPHop*                hop                     {nullptr};
    RSVPTimeValues*         time_values             {nullptr};
    RSVPResvConfirm*        resv_confirm            {nullptr};
    RSVPScope*              scope                   {nullptr};
    Vector<RSVPPolicyData*> policy_data             {};
    RSVPStyle*              style                   {nullptr};
    Vector<FlowDescriptor>  flow_descriptor_list    {};
};


/**
 * Struct to store pointers to the objects of a PATH_ERR message
 */
struct PathErr
{
    RSVPSession*            session                 {nullptr};
    RSVPErrorSpec*          error_spec              {nullptr};
    Vector<RSVPPolicyData*> policy_data             {};
    SenderDescriptor        sender                  {nullptr, nullptr};
};


/**
 * Struct to store pointers to the objects of a RESV_ERR message
 */
struct ResvErr
{
    RSVPSession*            session                 {nullptr};
    RSVPHop*                hop                     {nullptr};
    RSVPErrorSpec*          error_spec              {nullptr};
    RSVPScope*              scope                   {nullptr};
    Vector<RSVPPolicyData*> policy_data             {};
    RSVPStyle*              style                   {nullptr};
    FlowDescriptor          flow_descriptor         {nullptr, nullptr};
};


/**
 * Struct to store pointers to the objects of a PATH_TEAR message
 */
struct PathTear
{
    RSVPSession*            session                 {nullptr};
    RSVPHop*                hop                     {nullptr};
    RSVPSenderTemplate*     sender_template         {nullptr};
};


/**
 * Struct to store pointers to the objects of a RESV_TEAR message
 */
struct ResvTear
{
    RSVPSession*            session                 {nullptr};
    RSVPHop*                hop                     {nullptr};
    RSVPStyle*              style                   {nullptr};
    Vector<RSVPFilterSpec*> flow_descriptor_list    {};
    // FlowSpec objects and a Scope object may be included in the message but must be ignored
};


/**
 * Struct to store pointers to the objects of a RESV_CONF message
 */
struct ResvConf
{
    RSVPSession*            session                 {nullptr};
    RSVPErrorSpec*          error_spec              {nullptr};
    RSVPResvConfirm*        resv_confirm            {nullptr};
    RSVPStyle*              style                   {nullptr};
    Vector<FlowDescriptor>  flow_descriptor_list    {};
};


CLICK_ENDDECLS

#endif // CLICK_RSVPMESSAGE_HH
