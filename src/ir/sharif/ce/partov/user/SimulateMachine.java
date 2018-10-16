package ir.sharif.ce.partov.user;

import ir.sharif.ce.partov.base.ClientFramework;
import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Machine;
import ir.sharif.ce.partov.machine.ClientMachine;
import ir.sharif.ce.partov.machine.NATMachine;
import ir.sharif.ce.partov.machine.ServerMachine;

public class SimulateMachine extends Machine {
	ClientFramework cf;
	int cnt;
	SimpleMachine machine;
	public SimulateMachine(ClientFramework clientFramework, int count) {
		super(clientFramework, count);
		cf = clientFramework;
		cnt = count;
		// The machine instantiated.
		// Interfaces are not valid at this point.
	}

	public void initialize() {
		// TODO: Initialize your program here; interfaces are valid now.
		switch (getRule()) {
		case "NAT":
			machine = new NATMachine(this, iface);
			break;
		case "Client":
			machine = new ClientMachine(this, iface);
			break;
		case "Server":
			machine = new ServerMachine(this, iface);
			break;
		}
		machine.initialize();
	}

	public void processFrame(Frame frame, int ifaceIndex) {
		machine.processFrame(frame, ifaceIndex);
	}

	public void run() {
		machine.run();
	}
	
	public String getRule(){
		
		return getCustomInformation();
	}

}