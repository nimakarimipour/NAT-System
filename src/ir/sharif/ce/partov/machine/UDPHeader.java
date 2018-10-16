package ir.sharif.ce.partov.machine;

import ir.sharif.ce.partov.utils.Utility;

import java.util.Arrays;

public class UDPHeader {
	public final static int UDPHeader_LENGTH = 8;
	public final static short UDP_PROTOCOL = 0x11;
	private byte[] data;

	public UDPHeader() {
		data = new byte[UDPHeader_LENGTH];
		setDefaults();
	}

	public UDPHeader(byte[] packet, int pos) {
		data = new byte[UDPHeader_LENGTH];
		setDefaults();
		System.arraycopy(packet, pos, data, 0, UDPHeader_LENGTH);
	}

	private void setDefaults() {
		setLen(data.length);
		setSrcPort(0);
		setDestPort(0);
		setChecksum(0);
	}


	public void setSrcPort(int Source_Port) {
		System.arraycopy(Utility.getBytes((short) Source_Port), 0, data, 0, 2);
	}

	public short getSrcPort() {
		byte[] port = new byte[2];
		System.arraycopy(data, 0, port, 0, 2);
		return Utility.convertBytesToShort(port);
	}

	public void setDestPort(int Destination_Port) {
		System.arraycopy(Utility.getBytes((short) Destination_Port), 0, data, 2, 2);
	}

	public short getDestPort() {
		byte[] port = new byte[2];
		System.arraycopy(data, 2, port, 0, 2);
		return Utility.convertBytesToShort(port);
	}

	public void setLen(int Length) {
		System.arraycopy(Utility.getBytes((short) Length), 0, data, 4, 2);
	}

	public int getLen() {
		byte[] length = new byte[2];
		System.arraycopy(data, 4, length, 0, 2);
		return Utility.convertBytesToShort(length);
	}

	public void setChecksum(int Packet_Checksum) {
		System.arraycopy(Utility.getBytes((short) Packet_Checksum), 0, data, 6, 2);
	}

	public int getChecksum() {
		byte[] Packet_Checksum = new byte[2];
		System.arraycopy(data, 6, Packet_Checksum, 0, 2);
		return Utility.convertBytesToShort(Packet_Checksum);
	}

	public void setPayload(byte[] payload, int pos) {
		System.arraycopy(payload, 0, data, UDPHeader_LENGTH + pos, payload.length);
	}

	public byte[] getPayload(int pos, int len) {
		byte[] payload = new byte[len];
		System.arraycopy(data, UDPHeader_LENGTH + pos, payload, 0, len);
		return payload;
	}

	public void clear() {
		Arrays.fill(data, (byte) 0);
	}

	public int getSize() {
		return data.length;
	}

	public byte[] getData() {
		return data;
	}
}
