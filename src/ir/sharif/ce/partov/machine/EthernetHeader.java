package ir.sharif.ce.partov.machine;

import ir.sharif.ce.partov.utils.Utility;

import java.util.Arrays;

public class EthernetHeader {
	public final static int ETHERNET_LENGTH = 14;
	private byte data[] = new byte[ETHERNET_LENGTH];
	public static final byte BROADCAST[] = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF};

	public EthernetHeader() {
		setSrc(BROADCAST);
		setDest(BROADCAST);
		setType(IPv4Header.IP_PROTOCOL);
	}

	public EthernetHeader(byte[] src, byte[] type) {
		setSrc(src);
		setType(type);
	}

	public EthernetHeader(byte[] dest, byte[] src, int type) {
		setDest(dest);
		setSrc(src);
		byte[] type_data = Utility.getBytes(((short) type));
		setType(type_data);
	}

	public EthernetHeader(byte[] packet_data, int pos) {
		System.arraycopy(packet_data, pos, data, 0, ETHERNET_LENGTH);
	}

	public void setDest(byte[] data) {
		System.arraycopy(data, 0, this.data, 0, 6);
	}

	public void setSrc(byte[] data) {
		System.arraycopy(data, 0, this.data, 6, 6);
	}

	public void setType(byte[] data) {
		System.arraycopy(data, 0, this.data, 12, 2);
	}

	public void setType(int type) {
		byte[] type_data = {(byte) ((type >> 8) & 0xFF), (byte) (type & 0xFF)};
		setType(type_data);
	}

	public byte[] getDest() {
		byte[] dest = new byte[6];
		System.arraycopy(data, 0, dest, 0, 6);
		return dest;
	}

	public byte[] getSrc() {
		byte[] src = new byte[6];
		System.arraycopy(data, 6, src, 0, 6);
		return src;
	}

	public byte[] getTypeinBytes() {
		byte[] type = new byte[2];
		System.arraycopy(data, 12, type, 0, 2);
		return type;
	}

	public int getTypeinInt() {
		byte[] type = new byte[2];
		System.arraycopy(data, 12, type, 0, 2);
		return Utility.convertBytesToShort(type);
	}

	public void clear() {
		Arrays.fill(data, (byte) 0);
	}

	public byte[] getData() {
		return data;
	}

	public int getSize() {
		return data.length;
	}
}