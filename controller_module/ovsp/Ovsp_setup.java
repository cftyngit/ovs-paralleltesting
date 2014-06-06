package net.floodlightcontroller.ovsp;

import java.nio.ByteBuffer;

import net.floodlightcontroller.packet.IPv4;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=OVSPSetupSerializer.class)
public class Ovsp_setup {
	public static final byte HOST_SERVER = 1;
    public static final byte HOST_MIRROR = 2;
	protected byte hostType;
	protected setupHost host;
	
	public Ovsp_setup(byte hostType, setupHost hostConf) {
		this.hostType = hostType;
		this.host = hostConf;
	}
	
	public int getHostType() {
		return hostType;
	}
	
	public setupHost getHostConf() {
		return host;
	}
	
	public byte[] toByte()
	{
		byte[] hb = host.toByte();
		byte[] htb = new byte[] {hostType};
		byte[] pad = new byte[3];
		byte[] data = new byte[hb.length + htb.length + pad.length];
		ByteBuffer bb = ByteBuffer.wrap(data);
		bb.put(htb);
		bb.put(pad);
		bb.put(hb);
		return data;
	}
}


   