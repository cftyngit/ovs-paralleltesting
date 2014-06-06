package net.floodlightcontroller.ovsp;

import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

public class setupHost {
	protected int address; 
	protected MACAddress hostMac;
	
	
	public MACAddress getHostMac() {
		return hostMac;
	}
	
	public int getHostIP() {
		return address;
	}
	
	public setupHost setHostIP(int address)
	{
		this.address = address;
		return this;
	}
	
	public setupHost setHostMac(MACAddress mac) {
		this.hostMac = mac;
		return this;
	}
	
	public byte[] toByte()
	{
		byte[] data = new byte[MACAddress.MAC_ADDRESS_LENGTH + 4];
        ByteBuffer bb = ByteBuffer.wrap(data);
        bb.put(IPv4.toIPv4AddressBytes(address));
        bb.put(hostMac.toBytes());
        return data;
	}
}
