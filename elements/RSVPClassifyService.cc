#include <click/config.h>
#include <click/args.hh>

#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include "RSVPClassifyService.hh"

CLICK_DECLS


int RSVPClassifyService::configure(Vector<String>& config, ErrorHandler* errh){

    int result = Args(config, this, errh).read("RSVPNode", ElementCastArg("RSVPNode"), m_node).complete();

    if(result < 0){
        return result;
    }

    return 0;

}


void RSVPClassifyService::push(__attribute__((unused)) int port, Packet* p){

    // packet should be a udp packet as precondition

    // need ip header for src and dst address and protocol number
    const click_ip* ip_header = p->ip_header();
    in_addr src_addr = ip_header->ip_src;
    in_addr dst_addr = ip_header->ip_dst;

    //at the moment we only support UDP
    if(ip_header->ip_p == IP_PROTO_UDP){

        //need udp header for src and dst port
        const click_udp* udp_header = p->udp_header();
        uint16_t src_port = udp_header->uh_sport;
        uint16_t dst_port = udp_header->uh_dport;

        uint32_t temp1 = ((uint32_t) 0 << 16) | src_port;
        uint64_t src_key = ((uint64_t) src_addr.s_addr) << 32 | temp1;

        temp1 = ((uint32_t) IP_PROTO_UDP << 16) | dst_port;
        uint64_t session_key = ((uint64_t)dst_addr.s_addr << 32) | temp1;

        if(m_node->resv_ff_exists(src_key, session_key)){
            click_chatter("Packet classified as QoS (Port 1)");
            output(1).push(p);

        }

    }

    else{
        click_chatter("Tried to classify QoS on a non UDP package");
    }

    click_chatter("Packet classified as Best Effort");
    output(0).push(p);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPClassifyService)