elementclass RSVPPacketScheduler {

    input
        ->ip_classy::IPClassifier(ip dscp 0, ip dscp 1);

    ip_classy[0]
        -> best_effort_q::SimpleQueue
        -> [0]scheduler::SimplePrioSched;

    ip_classy[1]
        ->qos_q::SimpleQueue
        ->[1]scheduler;

    scheduler
        -> sched::Unqueue
        -> output;
}

