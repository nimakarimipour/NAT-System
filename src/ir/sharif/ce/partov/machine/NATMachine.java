package ir.sharif.ce.partov.machine;

import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Interface;
import ir.sharif.ce.partov.user.SimpleMachine;
import ir.sharif.ce.partov.user.SimulateMachine;
import ir.sharif.ce.partov.utils.Utility;

import java.util.ArrayList;
import java.util.Scanner;

import static ir.sharif.ce.partov.utils.Utility.convertBytesToShort;

public class NATMachine extends SimpleMachine {

    private ArrayList<NodeInfo> translatedNode;
    private ArrayList<Limit> limits;
    private int currentIp;
    private short currentPort;

    public NATMachine(SimulateMachine simulatedMachine, Interface[] iface) {
        super(simulatedMachine, iface);
    }


    public void initialize() {
        translatedNode = new ArrayList<>();
        limits = new ArrayList<>();
        currentIp = (iface[0].ip + 1);
        currentPort = 2000;
    }

    public void processFrame(Frame frame, int ifaceIndex) {


        print("Packet arrived at processFrame");



        byte[] data = new byte[frame.data.length];
        System.arraycopy(frame.data, 0, data, 0, data.length);
        EthernetHeader eth = new EthernetHeader(data, 0);
        if (eth.getTypeinInt() == ((int) IPv4Header.IP_PROTOCOL)) {
            IPv4Header iph = new IPv4Header(data, 14, 5);
            if (!validateChecksum(iph)) {
                System.out.println("invalid packet, dropped");
                return;
            }
            UDPHeader udph = new UDPHeader(data, 34);
            byte[] payload = new byte[frame.length - 42];
            System.arraycopy(data, 42, payload, 0, payload.length);
            iph.setTTL(iph.getTTL() - 1);
            iph.setChecksum((short) 0);
            iph.setChecksum(calChecksum(iph.getData()));
            if (iph.getDest() != iface[0].getIp()) {
                if (iph.getTTL() > 0)
                    if (ifaceIndex == 0) outToIn(eth, iph, udph, payload);
                    else intToOut(eth, iph, udph, payload);
            }
        }
    }

    private void outToIn(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload) {
        print("Packet from out wants to go in");
        NodeInfo node = findNodeViaPublic(iph.getDest(), udph.getDestPort());
        if (node != null && node.madeContact(iph.getSrc(), udph.getSrcPort())) {
            iph.setDest(node.getLocalIp());
            udph.setDestPort(node.getLocalPort());
            iph.setChecksum((short) 0);
            iph.setChecksum(calChecksum(iph.getData()));
            print("Translated");
            forwardFrame(eth, iph, udph, payload, false);
        } else {
            if (node != null) {
                System.out.println("outer packet dropped");
                byte[] newPayload = {0, 'd', 'r', 'o', 'p'};
                sendTo(iph.getSrc(), udph.getSrcPort(), newPayload, (short)1234);
                print("sent inform to: " + Utility.getIPString(iph.getSrc()) + " : " + udph.getSrcPort());
            }
        }
    }

    private void intToOut(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload) {
        NodeInfo node = findNodeViaLocal(iph.getSrc(), udph.getSrcPort());
        if (node == null) {
            if (portIsBlocked(udph.getSrcPort())) {
                sendPortResponse(eth, iph, udph);
                return;
            }
            int ip = currentIp;
            short port = currentPort;
            currentPort += 100;
            if (currentPort == 2300) {
                currentIp++;
                currentPort = 2000;
            }
            ConnectionInfo localInfo = new ConnectionInfo(iph.getSrc(), udph.getSrcPort());
            ConnectionInfo publicInfo = new ConnectionInfo(ip, port);
            node = new NodeInfo(localInfo, publicInfo);
            translatedNode.add(node);
        }
        translate(eth, iph, udph, payload, node.getPublicIp(), node.getPublicPort());
        node.addToMadeContact(iph.getDest(), udph.getDestPort());
    }

    private void sendPortResponse(EthernetHeader eth, IPv4Header iph, UDPHeader udph) {
        byte[] payload = {0, 'd', 'r', 'o', 'p'};
        sendTo(iph.getSrc(), udph.getSrcPort(), payload, (short)4321);
    }

    private boolean portIsBlocked(short port) {
        for (Limit l : limits) {
            if (port >= l.min && port <= l.max) return true;
        }
        return false;
    }

    private void translate(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload, int ip, short port) {
        iph.setSrc(ip);
        udph.setSrcPort(port);
        iph.setChecksum((short) 0);
        iph.setChecksum(calChecksum(iph.getData()));
        sendFrame(makeFrame(eth, iph, udph, payload), 0);
    }

    private NodeInfo findNodeViaLocal(int ip, short port) {
        for (NodeInfo c : translatedNode) {
            if (c.getLocalIp() == ip && c.getLocalPort() == port) return c;
        }
        return null;
    }

    private NodeInfo findNodeViaPublic(int ip, short port) {
        for (NodeInfo c : translatedNode) {
            if (c.getPublicIp() == ip && c.getPublicPort() == port) return c;
        }
        return null;
    }

    private void sendTo(int ip, short port, byte[] payload, short srcPort) {
        EthernetHeader eth = new EthernetHeader();
        IPv4Header iph = new IPv4Header();
        UDPHeader udph = new UDPHeader();
        iph.setDest(ip);
        iph.setSrc(iface[0].getIp());
        iph.setTotalLength(payload.length + 28);
        iph.setChecksum((short) 0);
        iph.setChecksum(calChecksum(iph.getData()));
        udph.setLen(payload.length + 8);
        udph.setDestPort(port);
        udph.setSrcPort(srcPort);
        print("In NAT: Send to - IP: " + Utility.getIPString(iph.getDest()));
        forwardFrame(eth, iph, udph, payload, true);
    }

    private void forwardFrame(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload, boolean changeMac) {
        for (int i = 1; i < iface.length; i++) {
            if (matchesInterface(iph, i)) {
                if (changeMac) eth.setSrc(iface[i].mac);
                print("In NAT: ForwardFrame - IP: " + Utility.getIPString(iph.getDest()));
                sendFrame(makeFrame(eth, iph, udph, payload), i);
                return;
            }
        }
        if(changeMac) eth.setSrc(iface[0].mac);
        eth.setType(IPv4Header.IP_PROTOCOL);
        sendFrame(makeFrame(eth, iph, udph, payload), 0);
    }

    private boolean matchesInterface(IPv4Header iph, int ifaceIndex) {
        return (iph.getDest() & iface[ifaceIndex].getMask()) == (iface[ifaceIndex].getIp() & iface[ifaceIndex].getMask());
    }

    private Frame makeFrame(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload) {
        byte[] ans = new byte[42 + payload.length];
        System.arraycopy(eth.getData(), 0, ans, 0, 14);
        System.arraycopy(iph.getData(), 0, ans, 14, 20);
        System.arraycopy(udph.getData(), 0, ans, 34, 8);
        System.arraycopy(payload, 0, ans, 42, payload.length);
        return new Frame(ans);
    }

    private short calChecksum(byte[] buf) {
        int length = buf.length;
        int i = 0;
        long sum = 0;
        long data;
        while (length > 1) {
            data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
            sum += data;
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
            i += 2;
            length -= 2;
        }
        if (length > 0) {
            sum += (buf[i] << 8 & 0xFF00);
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }
        }
        sum = ~sum;
        sum = sum & 0xFFFF;
        byte[] bytes = Utility.getBytes(sum);
        byte[] temp = new byte[2];
        System.arraycopy(bytes, bytes.length - 2, temp, 0, 2);
        return convertBytesToShort(temp);
    }

    private boolean validateChecksum(IPv4Header iph) {
        short checksum = iph.getChecksum();
        iph.setChecksum((byte) 0);
        boolean ans = checksum == calChecksum(iph.getData());
        iph.setChecksum(checksum);
        return ans;
    }

    private void print(String s){
        //System.out.println(s);
    }


    @SuppressWarnings("InfiniteLoopStatement")
    public void run() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            String command = scanner.nextLine();
            if (command.startsWith("block port range ") && command.substring(17).matches("\\d+\\s\\d+")) {
                String[] ranges = command.substring(17).split(" ");
                limits.add(new Limit(Short.parseShort(ranges[1]), Short.parseShort(ranges[0])));
            }else {
                if (command.equals("reset network settings")) {
                    System.out.println("please enter the base start number for port.");
                    currentPort = (short) (Short.parseShort(scanner.nextLine()));
                    for (NodeInfo n : translatedNode) {
                        byte[] payload = {readString("10000000")};
                        sendTo(n.getLocalIp(), n.getLocalPort(), payload, (short) 1234);
                    }
                    translatedNode.clear();
                    limits.clear();
                    currentIp = (iface[0].ip + 1);
                }
                else System.out.println("invalid command");
            }
        }
    }

    private byte readString(String s) {
        return (byte) (int) Integer.valueOf(s, 2);
    }

    public class Limit {
        short min, max;

        Limit(short max, short min) {
            this.max = max;
            this.min = min;
        }
    }


    public class ConnectionInfo {
        int ip;
        short port;

        ConnectionInfo(int ip, short port) {
            this.ip = ip;
            this.port = port;
        }

        public int getIp() {
            return ip;
        }

        public void setIp(int ip) {
            this.ip = ip;
        }

        public short getPort() {
            return port;
        }

        public void setPort(short port) {
            this.port = port;
        }
    }

    public class NodeInfo {
        ConnectionInfo localInfo, publicInfo;
        ArrayList<ConnectionInfo> madeContact;

        NodeInfo(ConnectionInfo localInfo, ConnectionInfo publicInfo) {
            this.localInfo = localInfo;
            this.publicInfo = publicInfo;
            madeContact = new ArrayList<>();
        }

        int getLocalIp() {
            return localInfo.ip;
        }

        short getLocalPort() {
            return localInfo.port;
        }

        int getPublicIp() {
            return publicInfo.ip;
        }

        short getPublicPort() {
            return publicInfo.port;
        }

        boolean madeContact(int ip, short port) {
            for (ConnectionInfo c : madeContact) {
                if (c.getIp() == ip && c.getPort() == port) return true;
            }
            return false;
        }

        void addToMadeContact(int ip, short port) {
            ConnectionInfo connectionInfo = new ConnectionInfo(ip, port);
            if (!madeContact.contains(connectionInfo)) madeContact.add(connectionInfo);
        }
    }
}