package ir.sharif.ce.partov.user;

import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Interface;

public abstract class SimpleMachine {
	private SimulateMachine simulatedMachine;
	protected Interface[] iface;
	protected SimpleMachine(SimulateMachine simulatedMachine, Interface[] iface){
		this.simulatedMachine = simulatedMachine;
		this.iface = iface;
	}
	
	public void sendFrame(Frame frame, int ifaceIndex) {
		simulatedMachine.sendFrame(frame, ifaceIndex);
	}
	
	abstract public void processFrame(Frame frame, int ifaceIndex);
	abstract public void run();
	abstract public void initialize();

}
