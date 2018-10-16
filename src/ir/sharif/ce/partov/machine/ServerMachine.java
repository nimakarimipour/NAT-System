package ir.sharif.ce.partov.machine;

import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Interface;
import ir.sharif.ce.partov.user.SimpleMachine;
import ir.sharif.ce.partov.user.SimulateMachine;
import ir.sharif.ce.partov.utils.Utility;

import java.util.HashMap;
import java.util.Scanner;

import static ir.sharif.ce.partov.utils.Utility.*;

public class ServerMachine extends SimpleMachine {

    private HashMap<Integer, InfoBox> infoHashMap;
    int ID;
    private static int IP_SERVER = 0x01010101;
    private static short IP_PORT = 1234;


    public ServerMachine(SimulateMachine simulatedMachine, Interface[] iface) {
        super(simulatedMachine, iface);
    }


    public void initialize() {
        infoHashMap = new HashMap<>();
        ID = 1;
    }

    public void processFrame(Frame frame, int ifaceIndex) {

        print("Packet arrived at processFrame");


        byte[] data = new byte[frame.data.length];
        System.arraycopy(frame.data, 0, data, 0, data.length);
        EthernetHeader eth = new EthernetHeader(data, 0);
        if (eth.getTypeinInt() == ((int) IPv4Header.IP_PROTOCOL)) {
            IPv4Header iph = new IPv4Header(data, 14, 5);
            if (!validateChecksum(iph)) return;
            UDPHeader udph = new UDPHeader(data, 34);
            byte[] payload = new byte[frame.length - 42];
            System.arraycopy(data, 42, payload, 0, payload.length);
            iph.setTTL(iph.getTTL() - 1);
            iph.setChecksum((short) 0);
            iph.setChecksum(calChecksum(iph.getData()));
            if (iph.getDest() != IP_SERVER) {
                if (iph.getTTL() > 0) forwardFrame(eth, iph, udph, payload, false);
            } else processRequest(iph, udph, payload);
        }
    }

    private void forwardFrame(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload, boolean changeMac) {
        print("packet not mine. IP: " + Utility.getIPString(iph.getDest()) + " Port: " + udph.getDestPort());
        for (int i = 0; i < iface.length; i++) {
            if (matchesInterface(iph, i)) {
                if (changeMac) eth.setSrc(iface[i].mac);
                sendFrame(makeFrame(eth, iph, udph, payload), i);
                print("Found the right interface");
                return;
            }
        }
        print("Changed mac.");
        if(changeMac) eth.setSrc(iface[0].mac);
        eth.setType(IPv4Header.IP_PROTOCOL);
        sendFrame(makeFrame(eth, iph, udph, payload), 0);
    }

    private boolean matchesInterface(IPv4Header iph, int ifaceIndex) {
        return (iph.getDest() & iface[ifaceIndex].getMask()) == (iface[ifaceIndex].getIp() & iface[ifaceIndex].getMask());
    }

    private void processRequest(IPv4Header iph, UDPHeader udph, byte[] payload) {
        String top = byteToString(payload[0]);
        if (payload[0] == 0) processAssigningID(iph, udph, payload);
        if (top.startsWith("001")) ProcessRequestGettingIP(iph, udph, payload[0]);
        if (top.startsWith("101")) updateClientInfo(iph, udph, payload);
        if (top.startsWith("110")) statusRespond(iph, udph, payload);
    }

    private void statusRespond(IPv4Header iph, UDPHeader udph, byte[] payload) {
        byte[] ipBytes = new byte[4];
        byte[] portBytes = new byte[2];
        System.arraycopy(payload, 1, ipBytes, 0, 4);
        System.arraycopy(payload, 5, portBytes, 0, 2);
        int localIp = convertBytesToInt(ipBytes);
        short localPort = convertBytesToShort(portBytes);
        if(localIp == iph.getSrc() && localPort == udph.getSrcPort()){
            byte[] newPayload = { readString("11100001") };
            sendTo(iph.getSrc(), udph.getSrcPort(), newPayload);

        }else {
            byte[] newPayload = { readString("11100000") };
            sendTo(iph.getSrc(), udph.getSrcPort(), newPayload);
        }
    }

    private void updateClientInfo(IPv4Header iph, UDPHeader udph, byte[] payload) {

        String top = byteToString(payload[0]);
        int oldId = (int) readString(top.substring(3));

        byte[] ipBytes = new byte[4];
        byte[] portBytes = new byte[2];
        System.arraycopy(payload, 1, ipBytes, 0, 4);
        System.arraycopy(payload, 5, portBytes, 0, 2);
        int ip = convertBytesToInt(ipBytes);
        short port = convertBytesToShort(portBytes);

        Info localInfo = new Info(ip, port);
        Info publicInfo = new Info(iph.getSrc(), udph.getSrcPort());
        InfoBox infoBox = new InfoBox(publicInfo, localInfo);

        infoHashMap.remove(oldId);
        infoHashMap.put(oldId, infoBox);

        System.out.println("id " + oldId + " updated to " + getIPString(publicInfo.ip) + ":" + publicInfo.port);
    }

    private void ProcessRequestGettingIP(IPv4Header iph, UDPHeader udph, byte top) {
        byte[] payload = new byte[13];
        payload[0] = top;
        int dest = readString(byteToString(top).substring(3));
        int from = findNodeID(iph.getSrc(), udph.getSrcPort());
        InfoBox box = infoHashMap.get(dest);
        if (from > 0 && box != null) {
            System.out.println(from + " wants info of node " + dest);
            System.arraycopy(getBytes(box.getLocalInfo().ip), 0, payload, 1, 4);
            System.arraycopy(getBytes(box.getLocalInfo().port), 0, payload, 5, 2);
            System.arraycopy(getBytes(box.getPublicInfo().ip), 0, payload, 7, 4);
            System.arraycopy(getBytes(box.getPublicInfo().port), 0, payload, 11, 2);
            sendTo(iph.getSrc(), udph.getSrcPort(), payload);
        } else System.out.println("id not exist, dropped");
    }

    private int findNodeID(int ip, short port) {
        for (Integer key : infoHashMap.keySet()) {
            InfoBox box = infoHashMap.get(key);
            if (box.getPublicInfo().ip == ip && box.getPublicInfo().port == port) return key;
        }
        return -1;
    }

    private void processAssigningID(IPv4Header iph, UDPHeader udph, byte[] payload) {
        int assignedKey = ID++;
        byte[] ipBytes = new byte[4];
        byte[] portBytes = new byte[2];
        System.arraycopy(payload, 1, ipBytes, 0, 4);
        System.arraycopy(payload, 5, portBytes, 0, 2);
        int ip = convertBytesToInt(ipBytes);
        short port = convertBytesToShort(portBytes);
        Info localInfo = new Info(ip, port);
        Info publicInfo = new Info(iph.getSrc(), udph.getSrcPort());
        InfoBox infoBox = new InfoBox(publicInfo, localInfo);
        infoHashMap.put(assignedKey, infoBox);
        System.out.println("new id " + assignedKey + " assigned to " + getIPString(publicInfo.ip) + ":" + publicInfo.port);
        byte[] data = {(byte) assignedKey};
        sendTo(iph.getSrc(), udph.getSrcPort(), data);
    }

    private void sendTo(int ip, short port, byte[] payload) {
        EthernetHeader eth = new EthernetHeader();
        IPv4Header iph = new IPv4Header();
        UDPHeader udph = new UDPHeader();
        iph.setDest(ip);
        iph.setSrc(IP_SERVER);
        udph.setDestPort(port);
        udph.setSrcPort(IP_PORT);
        iph.setTotalLength(payload.length + 28);
        iph.setChecksum((short) 0);
        iph.setChecksum(calChecksum(iph.getData()));
        udph.setLen(payload.length + 8);
        forwardFrame(eth, iph, udph, payload, true);
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

    private Frame makeFrame(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload) {
        byte[] ans = new byte[42 + payload.length];
        System.arraycopy(eth.getData(), 0, ans, 0, 14);
        System.arraycopy(iph.getData(), 0, ans, 14, 20);
        System.arraycopy(udph.getData(), 0, ans, 34, 8);
        System.arraycopy(payload, 0, ans, 42, payload.length);
        return new Frame(ans);
    }


    @SuppressWarnings("InfiniteLoopStatement")
    public void run() {
        Scanner scanner = new Scanner(System.in);
        while (true) scanner.nextLine();
    }

    private String byteToString(byte b) {
        return String.format("%8s", Integer.toBinaryString(((int) b + 256) % 256)).replace(' ', '0');
    }

    private byte readString(String s) {
        return (byte) (int) Integer.valueOf(s, 2);
    }

    private void print(String s){
        // System.out.println(s);
    }
}


class Info{
    int ip;
    short port;

    public Info(int ip, short port) {
        this.ip = ip;
        this.port = port;
    }
}

class InfoBox {
    Info[] infos;

    public InfoBox(Info publicInfo, Info localInfo) {
        this.infos = new Info[2];
        this.setPublicInfo(publicInfo);
        this.setLocalInfo(localInfo);
    }

    public void setPublicInfo(Info info) {
        infos[0] = info;
    }

    public void setLocalInfo(Info info) {
        infos[1] = info;
    }

    public Info getPublicInfo() {
        return infos[0];
    }

    public Info getLocalInfo() {
        return infos[1];
    }
}