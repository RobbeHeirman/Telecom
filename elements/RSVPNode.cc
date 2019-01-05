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
                        .read_mp("AddressInfo", addr)
                        .consume()};

    m_interfaces.push_back(addr);
    // Check whether the parse failed
    if (result < 0) {
        return -1;
    }

    while(!args.empty()){
        IPAddress addr;
        result = args.read_p("AddressInfo", addr).consume();
        m_interfaces.push_back(addr);
    }
    return 0;
}

int RSVPNode::release(const String& conf, Element *e, void*, ErrorHandler* errh){

    RSVPNode* me = (RSVPNode*) e;
    Vector<String> vconf;
    cp_argvec(conf, vconf);
    int session_id = 0;
    if(Args(vconf, me, errh).read_mp("SessionID", session_id).complete() < 0){
        return -1;
    }

    if(session_id >= me->m_local_session_id.size()){
        errh->error("Session with ID %d doesn't exist", session_id);
        return -1;
    }

    uint64_t ses_id = me->m_local_session_id[session_id];

    for(RSVPNode::FFReserveMap::iterator it = me->m_ff_resv_states.begin(); it != me->m_ff_resv_states.end(); it++){

        if( it->second.find(ses_id) != it->second.end() ) {

            ReserveState& rsv_state = it->second[ses_id];
            SenderID ssid = SenderID::from_rsvp_filter_spec(rsv_state.filterSpec);
            SessionID sesid = SessionID::from_rsvp_session(&rsv_state.session);

            if(me->m_path_state[ssid.to_key()].find(session_id) != me->m_path_state[ssid.to_key()].end()){
                click_chatter("Release handler vind pathstate niet");
            }
            else{

                PathState& pstate = me->m_path_state[ssid.to_key()][session_id];
                WritablePacket* p = me->generate_resv_tear(sesid, ssid, pstate.t_spec, me->m_interfaces[0]);
                me->ipencap(p, me->m_interfaces[0], rsv_state.prev_hop);
                me->output(0).push(p);
            }


        }
    }

    for(PathStateMap::iterator it = me->m_path_state.begin(); it != me->m_path_state.end(); it++){

        if( it->second.find(ses_id) != it->second.end() ) {

            PathState& pathstate = it->second[ses_id];
            SenderID ssid = SenderID::from_rsvp_sendertemplate(&pathstate.sender_template);
            SessionID sesd = SessionID::from_rsvp_session(&pathstate.session);

            WritablePacket* p = me->generate_path_tear(sesd, ssid, pathstate.t_spec, me->m_interfaces[0]);
            me->ipencap(p, me->m_interfaces[0], pathstate.session.dest_addr);
            me->output(0).push(p);
        }
    }

    return 0;
}

void RSVPNode::add_handlers() {

    add_write_handler("release", &release, (void*)0);
}

void RSVPNode::push(int port, Packet* p){
    // We know a RSVP message start with the RSVP header.
    // We can cast directly.
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};
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
    else{
        click_chatter("Couldnt't recognize message type %s", String(header->msg_type).c_str());
    }
    click_chatter("=====================================================================================================");
}

void RSVPNode::handle_path_message(Packet *p, int port) {
    // Block of info we need to find

    Path path {};
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};

     if(!find_path_ptrs( (const unsigned char*) header, path)){
         p->kill();
         if(path.session == nullptr or path.sender.sender == nullptr or path.sender.tspec == nullptr){
             click_chatter("???");
             SessionID ses_id{SessionID::from_rsvp_session(path.session)};
             SenderID sender_id{SenderID::from_rsvp_sendertemplate(path.sender.sender)};
             generate_path_err(ses_id, sender_id, *path.sender.tspec, path.error_code, path.error_value);
             return;
         }
         else{
             click_chatter("Couldn't find all the objects to generate error message");
             return;
         }

     } // function in abstract to find path ptrs


    // "State is defined by < session, sender template>"
    // Converting packets to 64 bit words so we can use those as keys for our HashMap.
    uint64_t byte_session{SessionID::to_key(*path.session)};
    uint64_t byte_sender{SenderID::to_key(*path.sender.sender)};

    click_chatter("Receiving path message from Session %s: ", String(byte_session).c_str());

    if(m_path_state.find(byte_sender) == m_path_state.end()){
        m_path_state[byte_sender] = HashTable <uint64_t, PathState>();
    }
    if(!path_state_exists(byte_sender, byte_session)) {
        click_chatter("New pathstate is being created...");
        // Making a state and filling it in
        PathState state;
        state.sender_template = *(path.sender.sender);
        state.session = *path.session;
        state.prev_hop = path.hop->address;
        for (int i = 0; i < path.policy_data.size(); i++) {
            state.policy_data.push_back(*(path.policy_data[i]));
        }
        state.t_spec = *(path.sender.tspec);

        // Time values
        state.R = this->calculate_refresh(RSVPElement::R);
        state.L = this->calculate_L(path.time_values->refresh);
        path.time_values->refresh = state.R;

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

        refresh->schedule_after_msec(state.R);
        timeout->schedule_after_msec(state.L);


        //Add the timer pointers to the struct
        state.refresh_timer = refresh;
        state.timeout_timer = timeout;
        state.path_call_back_data = path_callback_data;

        m_path_state[byte_sender][byte_session] = state;
        m_local_session_id.push_back(byte_session);
        click_chatter("Succes! Values = Previous Hop: %s, Refresh Timer: %s ms, Time to live: %s ms",
                String(state.prev_hop.unparse()).c_str(),
                String(state.R).c_str(),
                String(state.L).c_str());
    }
    else{
        click_chatter("This is a Path refresh message...");
        PathState& state = m_path_state[byte_sender][byte_session];

        state.sender_template = *(path.sender.sender);
        state.session = *path.session;
        state.prev_hop = path.hop->address;
        for (int i = 0; i < path.policy_data.size(); i++) {
            state.policy_data.push_back(*(path.policy_data[i]));
        }


        state.R = this->calculate_refresh(RSVPElement::R);
        state.L = this->calculate_L(state.R);
        path.time_values->refresh = state.R;
        state.is_timeout = false;
        click_chatter("Values = Previous Hop: %s, Refresh Timer: %s ms, Time to live: %s ms",
                      String(state.prev_hop.unparse()).c_str(),
                      String(state.R).c_str(),
                      String(state.L).c_str());
    }

    // Tell the IPEncapModule we keep on routing to the receiver
    ipencap(p, path.sender.sender->src_addr, path.session->dest_addr);
    output(port).push(p);
}

void RSVPNode::handle_resv_message(Packet *p, int port) {

    // Helping to find us our corresponding ptrs.
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};
    Resv resv;
    find_resv_ptrs((unsigned char*) header, resv);

    // We look for the corresponding session in our PathState Table.
    uint64_t session_key = SessionID::to_key(*resv.session);

    click_chatter("Receiving reserve message from Session %s: ", String(session_key).c_str());
    if(resv.style->sharing == 0b01 && resv.style->s_selection == 0b010) { //TODO: maybe we need to map those styles in an enum aswell
        // We loop over all flowDescriptors
        click_chatter("FF reserve style");
        for (auto i = 0; i < resv.flow_descriptor_list.size(); i++) {

            // Since this is FF style we look for the sender corresponding with the filterspec
            uint64_t address_key = SenderID::to_key(*(resv.flow_descriptor_list[i].filter_spec));
            if (m_path_state.find(address_key) != m_path_state.end()) {
                // We need the corresponding pathState
                if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()) {
                    click_chatter("PathState is here resuming...");
                    // need PHop from pathstate to forward
                    PathState &state = m_path_state[address_key][session_key];
                    // We make a new reservation state
                    // We check if this sender is already in State map. Else we make an empty entry for this sender
                    if (m_ff_resv_states.find(address_key) == m_ff_resv_states.end()) {
                        m_ff_resv_states[address_key] = HashTable<uint64_t, ReserveState>();
                    }

                    // We don't have this reservation in our reservation map
                    if (!resv_ff_exists(address_key, session_key)) {
                        click_chatter("Creating new Reservation state..");
                        // We add a new resv state here
                        ReserveState r_state;

                        //Fill in the reserve state data
                        r_state.session = *resv.session;
                        r_state.prev_hop = state.prev_hop;
                        r_state.next_hop = resv.hop->address;
                        r_state.flowSpec = *resv.flow_descriptor_list[i].flow_spec;
                        r_state.filterSpec = *resv.flow_descriptor_list[i].filter_spec;
                        r_state.R = this->calculate_refresh(resv.time_values->refresh);
                        r_state.L = this->calculate_L(resv.time_values->refresh);

                        // Time values
                        r_state.R = this->calculate_refresh(RSVPElement::R);
                        r_state.L = this->calculate_L(r_state.R);

                        // Create the callback data
                        ReserveCallbackData *rsv_callback = new ReserveCallbackData;
                        rsv_callback->sender_key = address_key;
                        rsv_callback->session_key = session_key;
                        rsv_callback->me = this;

                        // Create the refresh and timeout timers
                        Timer *refresh = new Timer(&RSVPNode::handle_reserve_refresh, rsv_callback);
                        Timer *timeout = new Timer(&RSVPNode::handle_reserve_time_out, rsv_callback);
                        refresh->initialize(this);
                        timeout->initialize(this);

                        // We schedule the first calls
                        refresh->schedule_after_msec(r_state.R);
                        timeout->schedule_after_msec(r_state.L);

                        //Add the timer pointers to the struct
                        r_state.refresh_timer = refresh;
                        r_state.timeout_timer = timeout;
                        r_state.call_back_data = rsv_callback;

                        m_ff_resv_states[address_key][session_key] = r_state;
                        click_chatter("Succes! Values = Previous Hop: %s Next Hop: %s, Refresh Timer: %s ms, Time to live: %s ms",
                                      String(r_state.prev_hop.unparse()).c_str(),
                                      String(r_state.next_hop.unparse()).c_str(),
                                      String(r_state.R).c_str(),
                                      String(r_state.L).c_str());

                    } else {

                        click_chatter("This is a Reserve refresh message...");

                        // We modify resv state here
                        ReserveState &r_state = m_ff_resv_states[address_key][session_key];
                        //Fill in the reserve state data
                        r_state.session = *resv.session;
                        r_state.prev_hop = state.prev_hop;
                        r_state.next_hop = resv.hop->address;
                        r_state.flowSpec = *resv.flow_descriptor_list[i].flow_spec;
                        r_state.filterSpec = *resv.flow_descriptor_list[i].filter_spec;
                        r_state.R = this->calculate_refresh(RSVPElement::R);
                        r_state.L = this->calculate_L(r_state.R);


                        r_state.is_timeout = false;

                        click_chatter("Values = Previous Hop: %s, Next Hop, Refresh Timer: %s ms, Time to live: %s ms",
                                      String(r_state.prev_hop.unparse()).c_str(),
                                      String(r_state.next_hop.unparse()).c_str(),
                                      String(r_state.R).c_str(),
                                      String(r_state.L).c_str());

                    }
                    //Signaling that the IPEncap with the correct src and dst addresses.
                    ipencap(p, m_interfaces[port], state.prev_hop);
                    output(port).push(p);
                } else {
                    click_chatter("Found a NONE existing session in receiver message.");
                }

            } else {
                click_chatter("Found a filter spec without matching sender spec!");
            }

        }
    }
    else{
        p->kill();
        click_chatter("Reservation style not known");
        SessionID ses_id = SessionID::from_key(session_key);
        for(int i = 0; i < resv.flow_descriptor_list.size(); i++){
            uint64_t address_key = SenderID::to_key(*resv.flow_descriptor_list[i].filter_spec);
            SenderID sender_id = SenderID::from_key(address_key);
            if(!path_state_exists(address_key, session_key)){
            }
            RSVPSenderTSpec t_spec = m_path_state[address_key][session_key].t_spec;
            WritablePacket* p = this->generate_resv_err(ses_id, sender_id,  t_spec, RSVPErrorSpec::UnkownResvStyle, 0);
            output(port).push(p);

        }


    }
}

bool RSVPNode::handle_path_tear_message(Packet *p, int port) {

    //Finding pointers
    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};

    PathTear tear;
    find_path_tear_ptrs((unsigned char*) header, tear);

    uint64_t sender_key = SenderID::to_key(*tear.sender_template);
    uint64_t session_key = SessionID::to_key(*tear.session);
    click_chatter("Receiving Path Tear message from %s", String(session_key).c_str());

    if(delete_state(sender_key, session_key, tear.hop->address)){
        delete_ff_rsv_state(sender_key, session_key);
        ipencap(p, tear.sender_template->src_addr, tear.session->dest_addr);
        output(port).push(p);
        return true;
    }

    else{
        p->kill(); // We did not find the session so the tear message is discarded.
        return false; // Nothing bad happend
    }

}

bool RSVPNode::handle_resv_tear_message(Packet* p, int port){

    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};

    ResvTear resv_tear;
    find_resv_tear_ptrs((unsigned char*) header, resv_tear);

    for(int i = 0; i < resv_tear.flow_descriptor_list.size(); i++){

        // FF so we look for the (sender, session) pair
        uint64_t address_key = SenderID::to_key(*resv_tear.flow_descriptor_list[i]);
        if(m_path_state.find(address_key) != m_path_state.end()) {

            uint64_t session_key = SessionID::to_key(*resv_tear.session);
            if (m_path_state[address_key].find(session_key) != m_path_state[address_key].end()) {

                // Now we found that pathstate we first make sure that we handle our IP addresses correctly.
                // So we make a copy of the Addres of NHOP.
                PathState* state = &m_path_state[address_key][session_key];
                in_addr addr = state->prev_hop;
                if(this->delete_ff_rsv_state(address_key, session_key)){ // If it's successfully deleted.
                    ipencap(p, m_interfaces[port], addr);
                    delete_state(address_key, session_key);
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

    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};

    PathErr path_err;
    find_path_err_ptrs((unsigned char*) header, path_err);

    // Converting to keys
    auto address_key{SenderID::to_key(*(path_err.sender.sender))};
    auto session_key{SessionID::to_key(*(path_err.session))};

    if(this->path_state_exists(address_key, session_key)){
        // We need to find the next hop
        PathState& state = this->m_path_state[address_key][session_key];

        // We forward it upstream with this interface as source and the NHOP stored in state
        ipencap(p, this->m_interfaces[port], state.prev_hop);
        output(port).push(p);
        return true;

    }

    //We just need to find the next hop
    return false;
}
bool RSVPNode::handle_resv_error_message(Packet* p, int port){

    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};
    ResvErr rsv_err;
    find_resv_err_ptrs((unsigned char*) header, rsv_err);

    auto sender_key{SenderID::to_key(*rsv_err.flow_descriptor.filter_spec)};
    auto session_key{SessionID::to_key(*rsv_err.session)};

    if(resv_ff_exists(sender_key, session_key)){

        ReserveState& state = m_ff_resv_states[sender_key][session_key];
        ipencap(p, m_interfaces[port], state.next_hop);
        output(port).push(p);
        return true;
    }

    //if(path_state_exists())

    return false;
}
bool RSVPNode::handle_confirmation_message(Packet* p, int port){

    const auto ip_header = (click_ip*) p->data();
    const auto header {(RSVPHeader*) (p->data() + 4 * ip_header->ip_hl)};


    ResvConf rsv_conf;
    find_resv_conf_ptrs((unsigned char*) header, rsv_conf);

    auto session_key{SessionID::to_key(*rsv_conf.session)};
    click_chatter("Receiving Confirmation message from session %s", String(session_key).c_str());
    for(auto i = 0 ; i < rsv_conf.flow_descriptor_list.size() ;  i++){
        auto sender_key{SenderID::to_key(*rsv_conf.flow_descriptor_list[i].filter_spec)};
        if(resv_ff_exists(sender_key, session_key)){
            ReserveState& state = m_ff_resv_states[sender_key][session_key];
            ipencap(p, m_interfaces[port], state.next_hop);
            click_chatter("Forwarding confirmation");
            click_chatter("Values: destination = %s", String(state.next_hop.unparse()).c_str());
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

uint32_t RSVPNode::calculate_refresh(uint32_t r) {

    return click_random(5, 15) * r / 10 ; // See RFC
}

uint32_t RSVPNode::calculate_L(uint32_t r){


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
}

//***********************************************


void RSVPNode::refresh_path_state(uint64_t sender_key, uint64_t session_key, Timer* t){

    click_chatter("Trying to fire a refresh message...");
    if(this->path_state_exists(sender_key, session_key)){

        //Sending a refresh path message
        PathState* state = &m_path_state[sender_key][session_key];
        WritablePacket* p = this->generate_path(
                SessionID::from_key(session_key),
                SenderID::from_key(sender_key),
                state->R,
                state->t_spec
                );
        click_chatter("Firing Path Refresh to %s: ", IPAddress(state->session.dest_addr).unparse().c_str());
        this->ipencap(p, m_interfaces[0], state->session.dest_addr);
        output(0).push(p);

        //And now we need to reschedule the timer, based on local R value for this session
        t->reschedule_after_msec(state->R);
        click_chatter("=================================================================================================");
    }
}

void RSVPNode::time_out_path_state(uint64_t sender_key, uint64_t session_key, Timer* t){
    click_chatter("checking a timeout of %s", String(session_key).c_str());
    // we check if this state is still in our table
    if(this->path_state_exists(sender_key, session_key)){
        PathState& state = m_path_state[sender_key][session_key];

        // Checks if this state is up to timeout, this means it did not receive a path_message yet
        if(state.is_timeout){
            click_chatter("PathState of Session %s timed out",String(session_key).c_str());
            this->delete_state(sender_key, session_key);
        }
        else{
            click_chatter("refreshed in time");
            // It was refreshed before timeout next timeout round the state will be destroyed.
            state.is_timeout = true;
            t->reschedule_after_msec(state.L);
        }
    }
}

void RSVPNode::refresh_reserve_state(uint64_t sender_key, uint64_t session_key, Timer* t){
    click_chatter("Trying to fire a reserveState refresh message");
    if(this->resv_ff_exists(sender_key, session_key) && this->path_state_exists(sender_key, session_key)){

        //Sending a refresh path message
        ReserveState& state = m_ff_resv_states[sender_key][session_key];
        PathState& p_state = m_path_state[sender_key][session_key];

        WritablePacket* p = this->generate_resv(
                SessionID::from_key(session_key),
                SenderID::from_key(sender_key),
                state.R,
                p_state.t_spec,
                false // No need for confirmation on refresh messages
                );

        this->ipencap(p, m_interfaces[0], state.prev_hop);
        click_chatter("Firing refresh message to %s", String(state.prev_hop.unparse()).c_str());
        output(0).push(p);
        //And now we need to reschedule the timer, based on local R value for this session
        t->reschedule_after_msec(state.R);
        click_chatter("=================================================================================================");
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
            t->reschedule_after_msec(state.L);
        }
    }

}

CLICK_ENDDECLS
EXPORT_ELEMENT(RSVPNode)