package ir.sharif.ce.partov.machine;

import ir.sharif.ce.partov.base.Frame;
import ir.sharif.ce.partov.base.Interface;
import ir.sharif.ce.partov.user.SimpleMachine;
import ir.sharif.ce.partov.user.SimulateMachine;
import ir.sharif.ce.partov.utils.Utility;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;

import static ir.sharif.ce.partov.utils.Utility.*;


public class ClientMachine extends SimpleMachine {

    private boolean connectionPending;
    private int ID;
    private short localPort;
    private boolean connected;

    private static int IP_SERVER = 0x01010101;
    private static short IP_PORT = 1234;

    private HashMap<Integer, KeyBox> keyBoxHashMap;
    private ArrayList<Integer> infoAskPendingsID;
    private ArrayList<Integer> sessionPending;
    private boolean statusPending = false;
    private int lastIDSent = 0;


    public ClientMachine(SimulateMachine simulatedMachine, Interface[] iface) {
        super(simulatedMachine, iface);
    }


    public void initialize() {
        connectionPending = false;
        connected = false;
        keyBoxHashMap = new HashMap<>();
        sessionPending = new ArrayList<>();
        infoAskPendingsID = new ArrayList<>();
        this.ID = 0;
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
            iph.setChecksum((byte)0);
            iph.setChecksum(convertBytesToShort(getBytes(calChecksum(iph.getData()))));
            if (iph.getDest() != iface[0].getIp()) {
                if (iph.getTTL() > 0) forwardFrame(eth, iph, udph, payload, false);
            } else processPacket(iph, udph, payload);
        }
    }

    private boolean validateChecksum(IPv4Header iph){
        short checksum = iph.getChecksum();
        iph.setChecksum((byte) 0);
        boolean ans = (checksum == calChecksum(iph.getData()));
        iph.setChecksum(checksum);
        return ans;
    }

    private void processPacket(IPv4Header iph, UDPHeader udph, byte[] payload) {

        print("packet is mine");


        String top = byteToString(payload[0]);

        print(top);


        if(top.startsWith("000")) {

            print("packet arrived at 000");
            if (connectionPending) {
                if (payload.length == 5 & checkTextInBytes(payload, 1, "drop") && udph.getSrcPort() == 4321) {
                    localPort += 100;
                    System.out.println("connection to server failed, retrying on port " + localPort);
                    makeConnection(localPort);
                    return;
                }
                if (payload.length == 1) {
                    this.ID = (int) readString(top.substring(3));
                    connectionPending = false;
                    connected = true;
                    System.out.println("Now My ID is " + ID);
                    return;
                }
            }
        }
        if(top.startsWith("001")){
            int index = readString(top.substring(3));
            if(infoAskPendingsID.contains(index)){
                addNodeToKnownNodes(index, payload);
                infoAskPendingsID.remove(new Integer(index));
            }
            else{
                print("Wasn't waiting for it");
            }
            return;
        }
        if(top.startsWith("010") & payload.length == 5){
            if(checkTextInBytes(payload, 1, "ping")){
                processResponseSession(iph, udph, readString(top.substring(3)));
                return;
            }
            if(checkTextInBytes(payload, 1, "pong")) {
                processRequestSession(iph, udph, readString(top.substring(3)));
                return;
            }
        }
        if(top.startsWith("011")){
            int from = (int) readString(top.substring(3));
            StringBuilder text = new StringBuilder();
            for (int i = 1; i < payload.length; i++) text.append((char) payload[i]);
            System.out.println("received msg from " + from + ":" + text);
            return;
        }

        if(top.startsWith("100")){
            print("Nat restarted");
            updateServer();
            return;
        }

        if(top.startsWith("111")){
            if (statusPending) {
                int flag = (int) readString(top.substring(3));
                if (flag == 1) {
                    System.out.println("direct");
                } else System.out.println("indirect");
                statusPending = false;
            }
            return;
        }
        print("Matched nothing doing nothing.");
    }

    private void updateServer(){
        byte[] payload = new byte[7];
        payload[0] = readString("101" + byteToString(ID));
        byte[] ipBytes = getBytes(iface[0].getIp());
        byte[] portBytes = getBytes(localPort);
        System.arraycopy(ipBytes, 0, payload, 1, 4);
        System.arraycopy(portBytes, 0, payload, 5, 2);
        sendTo(IP_SERVER, IP_PORT, payload);
    }

    private void processResponseSession(IPv4Header iph, UDPHeader udph, int id) {
        System.out.println("Connected to " + id);
        Key key = new Key(iph.getSrc(), udph.getSrcPort());
        KeyBox keyBox = new KeyBox(key, key);
        keyBox.setKey(key);
        if(keyBoxHashMap.containsKey(id)) keyBoxHashMap.remove(id);
        keyBoxHashMap.put(id, keyBox);
        byte[] payload = new byte[5];
        payload[0] = readString("010" + byteToString(ID));
        byte[] text = {'p', 'o', 'n', 'g'};
        System.arraycopy(text, 0, payload, 1, text.length);
        sendTo(iph.getSrc(), udph.getSrcPort(), payload);
    }

    private void processRequestSession(IPv4Header iph, UDPHeader udph, int id) {
        if(keyBoxHashMap.get(id) == null) return;
        if(!sessionPending.contains(id)) return;
        sessionPending.remove(new Integer(id));
        System.out.println("Connected to " + id);
        Key key = new Key(iph.getSrc(), udph.getSrcPort());
        keyBoxHashMap.get(id).setKey(key);
    }

    private void addNodeToKnownNodes(int id, byte[] payload) {

        print("addNodeToKnownNodes: " + id);


        byte[] localIP = new byte[4];
        byte[] localPort = new byte[2];
        byte[] publicIP = new byte[4];
        byte[] publicPort = new byte[2];
        System.arraycopy(payload, 1, localIP, 0, 4);
        System.arraycopy(payload, 5, localPort, 0, 2);
        System.arraycopy(payload, 7, publicIP, 0, 4);
        System.arraycopy(payload, 11, publicPort, 0, 2);
        Key publicKey = new Key(convertBytesToInt(publicIP), convertBytesToShort(publicPort));
        Key localKey = new Key(convertBytesToInt(localIP), convertBytesToShort(localPort));
        if(keyBoxHashMap.get(id) != null) keyBoxHashMap.remove(id);
        keyBoxHashMap.put(id, new KeyBox(publicKey, localKey));
        System.out.println("packet with (" + id + ", " + getIPString(localIP) + ", " +
        convertBytesToShort(localPort) + ", " + getIPString(publicIP) + ", "
                + convertBytesToShort(publicPort) + ") received");
    }

    private void forwardFrame(EthernetHeader eth, IPv4Header iph, UDPHeader udph, byte[] payload, boolean changeMac) {
        for (int i = 0; i < iface.length; i++) {
            if (matchesInterface(iph, i)) {
                if(changeMac) eth.setSrc(iface[i].mac);
                sendFrame(makeFrame(eth, iph, udph, payload), i);
                return;
            }
        }
        if(changeMac) eth.setSrc(iface[0].mac);
        eth.setType(IPv4Header.IP_PROTOCOL);
        sendFrame(makeFrame(eth, iph, udph, payload), 0);
    }

    private boolean matchesInterface(IPv4Header iph, int ifaceIndex){
        return (iph.getDest() & iface[ifaceIndex].getMask()) == (iface[ifaceIndex].getIp() & iface[ifaceIndex].getMask());
    }

    private void sendTo(int ip, short port, byte[] payload) {
        EthernetHeader eth = new EthernetHeader();
        IPv4Header iph = new IPv4Header();
        UDPHeader udph = new UDPHeader();
        iph.setDest(ip);
        iph.setSrc(iface[0].getIp());
        iph.setTotalLength(payload.length + 28);
        iph.setChecksum((short) 0);
        iph.setChecksum(calChecksum(iph.getData()));
        udph.setDestPort(port);
        udph.setSrcPort(this.localPort);
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

        while (true) {
            String command = scanner.nextLine();
            String[] tokens = command.split(" ");
            switch (tokens[0]) {
                case "make":
                    switch (tokens[2]) {
                        case "connection":
                            if (commandIsValid("connection", command)) makeConnection(Short.parseShort(tokens[7]));
                            break;
                        case "public":
                            if (commandIsValid("public", command)) makePublicSession(Integer.parseInt(tokens[5]));
                            break;
                        case "local":
                            if (commandIsValid("local", command)) makeLocalSession(Integer.parseInt(tokens[5]));
                            break;
                        default:
                            System.out.println("invalid command");
                    }
                    break;
                case "get":
                    if (commandIsValid("get", command)) getInfo(Integer.parseInt(tokens[3]));
                    break;
                case "send":
                    if (commandIsValid("send", command)) send(tokens, command);
                    break;

                case "status":
                    if (commandIsValid("status", command)) askStatus();
                    break;

                default:
                    System.out.println("invalid command");
            }
        }
    }

    private boolean commandIsValid(String type, String command) {
        switch (type) {
            case "connection":
                if (command.substring(0, 36).equals("make a connection to server on port ")
                        && command.substring(36).matches("\\d+")) return true;
                else System.out.println("invalid command");
                break;
            case "public":
                if (command.substring(0, 25).equals("make a public session to ")
                        && command.substring(25).matches("\\d+")) return true;
                else System.out.println("invalid command");
                break;
            case "local":
                if (command.substring(0, 24).equals("make a local session to ")
                        && command.substring(24).matches("\\d+")) return true;
                System.out.println("invalid command");
                break;
            case "get":
                if (command.substring(0, 12).equals("get info of ")
                        && command.substring(12).matches("\\d+")) return true;
                System.out.println("invalid command");
                break;
            case "send":
                if (command.substring(0, 12).equals("send msg to ") && command.indexOf(":") > 0
                        && command.substring(12, command.indexOf(":")).matches("\\d+")) return true;
                System.out.println("invalid command");
                break;

            case "status":
                return true;
        }
        return false;
    }

    private void send(String[] tokens, String message) {
        int dest = Integer.parseInt(tokens[3].substring(0, tokens[3].indexOf(":")));
        KeyBox destKeyBox = keyBoxHashMap.get(dest);
        if(destKeyBox != null  && destKeyBox.getKey() != null){
            message = message.substring(message.indexOf(":") + 1);
            byte[] payload = new byte[1 + message.length()];
            payload[0] = readString("011" + byteToString(ID));
            for (int i = 0; i < message.length(); i++) payload[i + 1] = (byte)message.charAt(i);
            lastIDSent = dest;
            sendTo(destKeyBox.getKey().ip, destKeyBox.getKey().port, payload);
            print("sent");
        }else System.out.println("please make a session first");
    }

    private void getInfo(int id) {
        byte[] payload = {readString("001" + byteToString(id))};
        sendTo(IP_SERVER, IP_PORT, payload);
        print("getInfo: " + id);
        infoAskPendingsID.add(id);
    }

    private void makeLocalSession(int id) {
        KeyBox keyBox = keyBoxHashMap.get(id);
        if(keyBox != null){
            byte[] payload = new byte[5];
            payload[0] = readString("010" + byteToString(ID));
            byte[] message = {'p', 'i', 'n', 'g'};
            System.arraycopy(message, 0, payload, 1, 4);
            if(!sessionPending.contains(id)) sessionPending.add(id);
            lastIDSent = -1;
            sendTo(keyBox.getLocalKey().ip, keyBox.getLocalKey().port, payload);
        }else System.out.println("info of node " + id + " was not received");
    }

    private void makePublicSession(int id) {
        KeyBox keyBox = keyBoxHashMap.get(id);
        if(keyBox != null){
            byte[] payload = new byte[5];
            payload[0] = readString("010" + byteToString(ID));
            byte[] message = {'p', 'i', 'n', 'g'};
            System.arraycopy(message, 0, payload, 1, message.length);
            if(!sessionPending.contains(id)) sessionPending.add(id);
            lastIDSent = -1;
            sendTo(keyBox.getPublicKey().ip, keyBox.getPublicKey().port, payload);
        }else System.out.println("info of node " + id + " was not received");
    }

    private void makeConnection(short port) {
        if(!connected) {
            if(port<= 1000 || port>= 5000) {
                System.out.println("invalid port");
                return;
            }
            byte[] payload = new byte[7];
            payload[0] = 0;
            byte[] ipBytes = getBytes(iface[0].getIp());
            byte[] portBytes = getBytes(port);
            System.arraycopy(ipBytes, 0, payload, 1, 4);
            System.arraycopy(portBytes, 0, payload, 5, 2);
            localPort = port;
            sendTo(IP_SERVER, IP_PORT, payload);
            connectionPending = true;
        }else System.out.println("you already have an id, ignored");
    }

    private void askStatus() {
        byte[] payload = new byte[7];
        payload[0] = readString("11000000");
        byte[] ipBytes = getBytes(iface[0].getIp());
        byte[] portBytes = getBytes(localPort);
        System.arraycopy(ipBytes, 0, payload, 1, 4);
        System.arraycopy(portBytes, 0, payload, 5, 2);
        sendTo(IP_SERVER, IP_PORT, payload);
        statusPending = true;
    }


    private String byteToString(byte b) {
        return String.format("%8s", Integer.toBinaryString(((int) b + 256) % 256)).replace(' ', '0');
    }

    private String byteToString(int b) {
        String format = "%" + 5 + "s";
        return String.format(format, Integer.toBinaryString((b + 256) % 256)).replace(' ', '0');
    }

    private boolean checkTextInBytes(byte[] payload, int start, String text) {
        if(start + text.length() > payload.length) return false;
        for (int i = 0; i < text.length(); i++) if(payload[i + start] != text.charAt(i)) return false;
        return true;
    }

    private byte readString(String s) {
        return (byte) (int) Integer.valueOf(s, 2);
    }


    private void print(String s){
        // System.out.println(s);
    }
}

class Key {
    int ip;
    short port;

    Key(int ip, short port) {
        this.ip = ip;
        this.port = port;
    }
}

class KeyBox{
    private Key[] infos;

    KeyBox(Key publicInfo, Key localInfo) {
        this.infos = new Key[3];
        this.setPublicKey(publicInfo);
        this.setLocalKey(localInfo);
    }

    private void setPublicKey(Key info){
        infos[0] = info;
    }

    private void setLocalKey(Key info){
        infos[1] = info;
    }

    Key getPublicKey(){
        return infos[0];
    }

    Key getLocalKey(){
        return infos[1];
    }

    Key getKey(){
        return infos[2];
    }

    void setKey(Key realKey){
        infos[2] = realKey;
    }
}