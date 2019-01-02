#include <click/config.h>
#include <click/args.hh>
#include <click/glue.hh>
#include "RSVPNode.hh"

CLICK_DECLS

RSVPNode::RSVPNode():RSVPElement() {}

int RSVPNode::configure(Vector<String>& config, ErrorHandler *const errh) {

    Args args(config, this, errh);
    // Parse the config vector
    IPAddress addr;
    int result {args
                        .read_mp("IPENCAP", ElementCastArg("IPEncap"), m_ipencap)
                        .read_mp("AddressInfo", addr)
                        .consume()};

    m_interfaces.push_back(addr);
    // Check whether the parse failed
    if (result < 0) {
        m_ipencap = nullptr;
        return -1;
    }

    while(!args.empty()){
        IPAddress addr;
        result = args.read_p("AddressInfo", addr).consume();
        m_interfaces.push_back(addr);
    }
    return 0;
}


void RSVPNode::push(int port, Packet* p){

    // We know a RSVP message start with the RSVP header.
    // We can cast directly.
    RSVPHeader* header = (RSVPHeader*) p->data();

    // If we receive a PATH message
    if(header->msg_type == RSVPHeader::Type::Path){
        handle_path_message(p, port);
    }

    else if (header->msg_type == RSVPHeader::Type::Resv){
        handle_resv_message(p, port);
    }

    else if (header->msg_type == RSVPHeader::Type::PathTear){
        if(!this->handle_path_tear_message(p, port)){ // Then the package is killed and not forwarded.
            return;
        }
    }

    else if(header->msg_type == RSVPHeader::Type::ResvTear){
        if(!this->handle_resv_tear_message(p, port)){
            return;;
        }
    }

    else if(header->msg_type == RSVPHeader::Type::PathErr){
        if(!this->handle_path_error_message(p, port)){
            return;
        }
    }

    else if(header->msg_type == RSVPHeader::Type::ResvErr){
        if(!this->handle_resv_error_message(p, port)){
            return;
        }
    }
    else if(header->msg_type == RSVPHeader::Type::ResvConf){
        if(!this->handle_confirmation_message(p, port)){
            return;
        }
    }
    output(port).push(p);
}

void RSVPNode::handle_path_message(Packet *p, int port) {
    // TODO: Timed path messages to be resend.
    // Block of info we need to find
    Path path {};
    find_path_ptrs(p, path); // function in abstract to find path ptrs


    // "State is defined by < session, sender template>"
    // Converting packets to 64 bit words so we can use those as keys for our HashMap.
    uint64_t byte_session = this->session_to_key(path.session);
    uint64_t byte_sender = this->sender_template_to_key(path.sender.sender);

    if(m_path_state.find(byte_sender) == m_path_state.end()){
        m_path_state[byte_sender] = HashTable <uint64_t, PathState>();
    }
    if(path_state_exists(byte_sender, byte_session)) {

        // Making a state and filling it in
        PathState state;
        state.sender_template = *(path.sender.sender);
        path.session = path.session;
        state.prev_hop = path.hop->address;
        for (int i = 0; i < path.policy_data.size(); i++) {
            state.policy_data.push_back(*(path.policy_data[i]));
        }
        state.t_spec = *(path.sender.tspec);

        // Time values
        state.R = this->calculate_refresh(path.time_values->refresh);
        state.L = this->calculate_L(path.time_values->refresh);

        //Timing the whole thing.
        // First we create the callback data.
        PathCallbackData *path_callback_data = new PathCallbackData();
        path_callback_data->session_key = byte_session;
        path_callback_data->sender_key = byte_sender;
        path_callback_data->me = this;

        // Create the refresh and timeout timers
        Timer *refresh = new Timer(&RSVPNode::handle_path_refresh, path_callback_data);
        Timer *timeout = new Timer(&RSVPNode::handle_path_time_out, path_callback_data);
        refresh->initialize(this);
        timeout->initialize(this);

        // We schedule the first calls
        refresh->schedule_after_msec(state.R * 100);
        timeout->schedule_after_msec(state.L * 100);

        //Add the timer pointers to the struct
        state.refresh_timer = refresh;
        state.timeout_timer = timeout;

        m_path_state[byte_sender][byte_session] = state;
    }
    else{

        PathState& state = m_path_state[byte_sender][byte_session];

        state.sender_template = *(path.sender.sender);
        path.session = path.session;
        state.prev_hop = path.hop->address;
        for (int i = 0; i < path.policy_data.size(); i++) {
            state.policy_data.push_back(*(path.policy_data[i]));
        }
        state.t_spec = *(path.sender.tspec);

        // Time values
        state.R = this->calculate_refresh(path.time_values->refresh);
        state.L = this->calculate_L(path.time_values->refresh);

        //PathState had a refresh message
        state.is_timeout = false;
    }

    // TODO: NEEDS TO BE CHANGED TO SET IP DST DIRECTLY
    // Tell the IPEncapModule we keep on routing to the receiver
    set_ipencap(path.sender.sender->src_addr, path.session->dest_addr);
    output(port).push(p);
}

void RSVPNode::handle_resv_message(Packet *p, int port) {

    // Helping to find us our corresponding ptrs.
    Resv resv;
    find_resv_ptrs(p, resv);

    // We loop over all flowDescriptors
    for(auto i = 0; i < resv.flow_descriptor_list.size(); i++){

        // Since this is FF style we look for the sender corresponding with the filterspec
        uint64_t address_key = SenderID::to_key(*(resv.flow_descriptor_list[i].filter_spec));
        if(m_path_state.find(address_key) != m_path_state.end()) {

            // We look for the corresponding session in our PathState Table.
            uint64_t session_key = session_to_key(resv.session);
            if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()){

                //TODO: Pass to admission/Policy control should happen here.

                // We make a new reservation state
                // We check if this sender is already in State map. Else we make an empty entry for this sender
                if(m_ff_resv_states.find(address_key) == m_ff_resv_states.end()){
                    m_ff_resv_states[address_key] = HashTable < uint64_t, ReserveState >();
                }


                // We add a new resv state here, modification also happens this way
                ReserveState r_state;
                r_state.flowSpec = *resv.flow_descriptor_list[i].flow_spec;
                r_state.next_hop = resv.hop->address;
                m_ff_resv_states[address_key][session_key] = r_state;

                // need PHop from pathstate to forward
                PathState &state = m_path_state[address_key][session_key];


                //Signaling that the IPEncap with the correct src and dst addresses.
                // TODO: THIS IS NOT GOOD, Shouldn't strip IP header and place new one
                set_ipencap(m_interfaces[port], state.prev_hop);
                output(port).push(p);
            }
            else {
                click_chatter("Found a NONE existing session in receiver message.");
            }

        }
        else{
            click_chatter("Found a filter spec without matching sender spec!");
        }

    }


}

bool RSVPNode::handle_path_tear_message(Packet *p, int port) {

    PathTear tear;
    find_path_tear_ptrs(p, tear);

    uint64_t sender_key = this->sender_template_to_key(tear.sender_template);
    uint64_t session_key = this->session_to_key(tear.session);

    if(delete_state(sender_key, session_key, tear.hop->address)){
        set_ipencap(tear.sender_template->src_addr, tear.session->dest_addr);
        output(port).push(p);
        return true;
    }

    else{
        p->kill(); // We did not find the session so the tear message is discarded.
        return false; // Nothing bad happend
    }

}

bool RSVPNode::handle_resv_tear_message(Packet* p, int port){

    ResvTear resv_tear;
    find_resv_tear_ptrs(p, resv_tear);

    for(int i = 0; i < resv_tear.flow_descriptor_list.size(); i++){

        // FF so we look for the (sender, session) pair
        uint64_t address_key = SenderID::to_key(*resv_tear.flow_descriptor_list[i]);
        if(m_path_state.find(address_key) != m_path_state.end()) {

            uint64_t session_key = session_to_key(resv_tear.session);
            if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()) {

                // Now we found that pathstate we first make sure that we handle our IP addresses correctly.
                // So we make a copy of the Addres of NHOP.
                PathState* state = &m_path_state[address_key][session_key];
                in_addr addr = state->prev_hop;
                if(this->delete_state(address_key, session_key, state->prev_hop, false)){ // If it's successfully deleted.
                    set_ipencap(m_interfaces[port], addr);
                    output(port).push(p);

                }

                else{ // If not we discard it.
                    p->kill();
                }

                // Now we have to delete this state

            }
            else {
                click_chatter("Found a NONE existing session in receiver message.");
                return  false;
            }

        }
        else{
            click_chatter("Found a filter spec without matching sender in Pathstate!");
            return  false;
        }
    }

    return false;

}
bool RSVPNode::handle_path_error_message(Packet* p, int port){

    PathErr path_err;
    find_path_err_ptrs(p, path_err);

    // Converting to keys
    auto address_key{SenderID::to_key(*(path_err.sender.sender))};
    auto session_key{SessionID::to_key(*(path_err.session))};

    if(this->path_state_exists(address_key, session_key)){
        // We need to find the next hop
        PathState& state = this->m_path_state[address_key][session_key];

        // We forward it upstream with this interface as source and the NHOP stored in state
        set_ipencap(this->m_interfaces[port], state.prev_hop);
        output(port).push(p);
        return true;

    }

    //We just need to find the next hop
    return false;
}
bool RSVPNode::handle_resv_error_message(Packet* p, int port){

    ResvErr rsv_err;
    find_resv_err_ptrs(p, rsv_err);

    auto sender_key{SenderID::to_key(*rsv_err.flow_descriptor.filter_spec)};
    auto session_key{SessionID::to_key(*rsv_err.session)};

    if(resv_ff_exists(sender_key, session_key)){

        ReserveState& state = m_ff_resv_states[sender_key][session_key];
        set_ipencap(m_interfaces[port], state.next_hop);
        output(port).push(p);
        return true;
    }

    //if(path_state_exists())

    return false;
}
bool RSVPNode::handle_confirmation_message(Packet* p, int port){

    ResvConf rsv_conf;
    find_resv_conf_ptrs(p, rsv_conf);

    auto session_key{SessionID::to_key(*rsv_conf.session)};
    for(auto i = 0 ; i < rsv_conf.flow_descriptor_list.size() ;  i++){
        auto sender_key{SenderID::to_key(*rsv_conf.flow_descriptor_list[i].filter_spec)};
        if(resv_ff_exists(sender_key, session_key)){
            ReserveState& state = m_ff_resv_states[sender_key][session_key];
            set_ipencap(m_interfaces[port], state.next_hop);
            output(port).push(p);
        }
    }
    return true;
}

bool RSVPNode::delete_state(const uint64_t& sender_key, const uint64_t& session_key, const in_addr& prev_hop, bool is_path){

    if(this->m_path_state.find(sender_key) != this->m_path_state.end()) {
        if (this->m_path_state[sender_key].find(session_key) != this->m_path_state[session_key].end()) {
            if (prev_hop == (m_path_state[sender_key][session_key]).prev_hop.in_addr() or !is_path) { // if the hop is different no effect
                click_chatter(String("Erasing session: ", session_key).c_str());
                this->m_path_state[sender_key].erase(session_key);

                if(this->m_path_state[sender_key].empty()){
                    this->m_path_state.erase(sender_key);
                }
                return true;
            }
        }
    }

    return false;
}

bool RSVPNode::delete_state(const uint64_t& sender_key, const uint64_t& session_key){

    if(this->m_path_state.find(sender_key) != this->m_path_state.end()) {
        if (this->m_path_state[sender_key].find(session_key) != this->m_path_state[session_key].end()) {
            click_chatter(String("Erasing session: ", session_key).c_str());
            this->m_path_state[sender_key].erase(session_key);

            if(this->m_path_state[sender_key].empty()){
                this->m_path_state.erase(sender_key);
            }
            return true;
        }
    }

    return false;
}

bool RSVPNode::delete_ff_rsv_state(const uint64_t& sender_key, const uint64_t& session_key){

    if(this->m_ff_resv_states.find(sender_key) != this->m_ff_resv_states.end()) {
        if (this->m_ff_resv_states[sender_key].find(session_key) != this->m_ff_resv_states[session_key].end()) {
            click_chatter(String("Erasing session: ", session_key).c_str());
            this->m_ff_resv_states[sender_key].erase(session_key);

            if(this->m_ff_resv_states[sender_key].empty()){
                this->m_ff_resv_states.erase(sender_key);
            }
            return true;
        }
    }

    return false;
}


bool RSVPNode::path_state_exists(const uint64_t& sender_key, const uint64_t& session_key){
    if(m_path_state.find(sender_key) != m_path_state.end()) {
        // We look for the corresponding session in our PathState Table.
        if (m_path_state[sender_key].find(session_key) != m_path_state[sender_key].end()){
            return true;
        }
    }
    return false;
}


bool RSVPNode::resv_ff_exists(const uint64_t &sender_key, const uint64_t &session_key) {

    if(m_ff_resv_states.find(sender_key) != m_ff_resv_states.end()){

        if(m_ff_resv_states[sender_key].find(session_key) != m_ff_resv_states[sender_key].end()){

            return true;
        }
    }
    return false;
}

float RSVPNode::calculate_refresh(float r) {

    return click_random(5, 15) / 10 * r; // See RFC
}

float RSVPNode::calculate_L(float r){


    return (K + 0.5) * 1.5 * r; // See RFC on calculating L value
}

void RSVPNode::handle_path_refresh(Timer* timer, void* data){

    PathCallbackData* path = (PathCallbackData*) data;
    assert(path);
    path->me->refresh_path_state(path->sender_key, path->session_key, timer);

}
void RSVPNode::handle_path_time_out(Timer* timer, void* data){

    auto path = (PathCallbackData*) data;
    assert(path);
    path->me->time_out_path_state(path->sender_key, path->session_key, timer);
}

void RSVPNode::handle_reserve_refresh(Timer* timer, void* data){

    auto rsv = (ReserveCallbackData*) data;
    assert(rsv);
    rsv->me->refresh_reserve_state(rsv->sender_key, rsv->session_key, timer);
}
void RSVPNode::handle_reserve_time_out(Timer* timer, void* data){

    auto rsv = (ReserveCallbackData*) data;
    assert(rsv);
    rsv->me->time_out_reserve_state(rsv->sender_key, rsv->session_key, timer);

    delete rsv;
}


//***********************************************


void RSVPNode::refresh_path_state(uint64_t sender_key, uint64_t session_key, Timer* t){

    if(this->path_state_exists(sender_key, session_key)){
        //Sending a refresh path message
        //TODO: the SetIPEncap needs to be changed here aswell.
        PathState* state = &m_path_state[sender_key][session_key];
        WritablePacket* p = this->generate_path(state);
        this->set_ipencap(state->sender_template.src_addr, state->session.dest_addr);
        output(0).push(p);

        //And now we need to reschedule the timer, based on local R value for this session
        t->reschedule_after_msec(state->R * 100);
    }
}

void RSVPNode::time_out_path_state(uint64_t sender_key, uint64_t session_key, Timer* t){

    // we check if this state is still in our table
    if(this->path_state_exists(sender_key, session_key)){

        PathState& state = m_path_state[sender_key][session_key];

        // Checks if this state is up to timeout, this means it did not receive a path_message yet
        if(state.is_timeout){
            this->delete_state(sender_key, session_key);
        }
        else{
            // It was refreshed before timeout next timeout round the state will be destroyed.
            state.is_timeout = true;
            t->reschedule_after_msec(state.L * 100);
        }
    }
}

void RSVPNode::refresh_reserve_state(uint64_t sender_key, uint64_t session_key, Timer* t){

    if(this->resv_ff_exists(sender_key, session_key)){

        //Sending a refresh path message
        //TODO: the SetIPEncap needs to be changed here aswell.
        ReserveState& state = m_ff_resv_states[sender_key][session_key];
        WritablePacket* p = this->generate_resv(state);
        this->set_ipencap(state.filterSpec.src_addr, state.session.dest_addr);
        output(0).push(p);

        //And now we need to reschedule the timer, based on local R value for this session
        t->reschedule_after_msec(state.R * 100);
    }
}

void RSVPNode::time_out_reserve_state(uint64_t sender_key, uint64_t session_key, Timer* t){

    // we check if this state is still in our table
    if(this->resv_ff_exists(sender_key, session_key)){

        ReserveState& state = m_ff_resv_states[sender_key][session_key];

        // Checks if this state is up to timeout, this means it did not receive a path_message yet
        if(state.is_timeout){
            this->delete_ff_rsv_state(sender_key, session_key);
        }
        else{
            // It was refreshed before timeout next timeout round the state will be destroyed.
            state.is_timeout = true;
            t->reschedule_after_msec(state.L * 100);
        }
    }

}



WritablePacket* RSVPNode::generate_path(PathState* state) {

    // Create a new packet
    const unsigned int size {sizeof(RSVPHeader)     + sizeof(RSVPSession)        + sizeof(RSVPHop)
                             + sizeof(RSVPTimeValues) + sizeof(RSVPSenderTemplate) + sizeof(RSVPSenderTSpec)};
    WritablePacket* const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader        ::write(pos_ptr, RSVPHeader::Path);
    RSVPSession       ::write(pos_ptr, state->session.dest_addr, state->session.proto, state->session.dest_port);
    RSVPHop           ::write(pos_ptr, state->prev_hop); // doesn't matter will be replaced later by correct outgoing interface
    RSVPTimeValues    ::write(pos_ptr, state->R); // R value of this node needs to be passed to the next node.
    RSVPSenderTemplate::write(pos_ptr, state->sender_template.src_addr, state->sender_template.src_port);
    RSVPSenderTSpec   ::write(pos_ptr, state->t_spec.r, state->t_spec.b, state->t_spec.p,  state->t_spec.m , state->t_spec.M);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader        ::complete(packet, size);
    return packet;
}

WritablePacket* RSVPNode::generate_resv(ReserveState& r_state ) {

    // Create a new packet
    const unsigned long size {sizeof(RSVPHeader)     + sizeof(RSVPSession)                    + sizeof(RSVPHop)
                              + sizeof(RSVPTimeValues) + sizeof(RSVPStyle)
                              + sizeof(RSVPFlowSpec)   + sizeof(RSVPFilterSpec)};
    WritablePacket *const packet {Packet::make(s_headroom, nullptr, size, 0)};
    if (not packet)
        return nullptr;

    // Set all bits in the new packet to 0
    auto pos_ptr {packet->data()};
    memset(pos_ptr, 0, size);

    // The write functions return a pointer to the position right after the area they wrote to
    RSVPHeader    ::write(pos_ptr, RSVPHeader::Resv);
    RSVPSession   ::write(pos_ptr, r_state.session.dest_addr, r_state.session.proto, r_state.session.dest_port);
    RSVPHop       ::write(pos_ptr, r_state.next_hop);
    RSVPTimeValues::write(pos_ptr, r_state.R);

    RSVPStyle     ::write(pos_ptr);
    RSVPFlowSpec  ::write(pos_ptr, r_state.flowSpec.r, r_state.flowSpec.b, r_state.flowSpec.p, r_state.flowSpec.m, r_state.flowSpec.M);
    RSVPFilterSpec::write(pos_ptr, r_state.filterSpec.src_addr, r_state.filterSpec.src_port);

    // Complete the header by setting the size and checksum correctly
    RSVPHeader    ::complete(packet, size);
    return packet;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)