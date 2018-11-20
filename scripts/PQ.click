source::RandomSource(64, LIMIT 30, BURST 30);
divider::RandomSwitch;
the_end::Discard;
classy::IPClassifier(tos == 0, tos == 32);
scheduler::PrioSched;
encap1:: IPEncap(4, 10.0.0.1, 10.0.0.2, TOS 0);
encap2:: IPEncap(4, 10.0.0.3, 10.0.0.2, TOS 32)

source
	-> divider;

divider[0]
	-> encap1 
	-> classy;

divider[1]
	-> encap2
	-> classy;

classy[0]
	-> Queue
	-> [0]scheduler;

classy[1]
	-> Queue
	-> [1]scheduler ;

scheduler
	->DelayUnqueue(5)
	->IPPrint
	->the_end

	




