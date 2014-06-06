package net.floodlightcontroller.ovsp;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.counter.ICounterStoreService;
import net.floodlightcontroller.loadbalancer.ILoadBalancerService;
import net.floodlightcontroller.loadbalancer.LoadBalancer;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.util.OFMessageDamper;

public class Ovsp_controller implements IFloodlightModule, IOFMessageListener , IOVSPControllerService{
	protected IFloodlightProviderService floodlightProvider;
	protected static Logger log = LoggerFactory.getLogger(LoadBalancer.class);
	protected ICounterStoreService counterStore;
    protected OFMessageDamper messageDamper;
    protected IRestApiService restApi;
	
    //Copied from Forwarding with message damper routine for pushing proxy Arp 
    protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // ms. 
    protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms 
    
    @Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
    	Collection<Class<? extends IFloodlightService>> l = 
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IOVSPControllerService.class);
        return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = 
                new HashMap<Class<? extends IFloodlightService>,
                    IFloodlightService>();
        m.put(IOVSPControllerService.class, this);
        return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = 
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		counterStore = context.getServiceImpl(ICounterStoreService.class);
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY, 
                EnumSet.of(OFType.FLOW_MOD),
                OFMESSAGE_DAMPER_TIMEOUT);
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new OVSPWebRoutable());
		//floodlightProvider.getControllerInfo(type)
		
	}

	@Override
	public String getName() {
		return "ovsp_controller";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && (name.equals("topology")
				|| name.equals("devicemanager") || name.equals("virtualizer")));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		/*Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
				IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IPacket pkt = eth.getPayload();
		//byte[] mac = sw.getPort(OFPort.OFPP_LOCAL.getValue()).getHardwareAddress();
		byte[] mac_src = {0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00};
		byte[] mac = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
		System.out.printf("LOCAL PORT MAC = %X:%X:%X:%X:%X:%X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		System.out.printf("LOCAL PORT IP = %s\n", ((InetSocketAddress)sw.getInetAddress()).getAddress().getHostAddress());*/
		/*Map<String, Object> m = floodlightProvider.getControllerInfo("summary");
		for (String key: m.keySet()) {

		    System.out.println("key : " + key);
		    //System.out.println("value : " + m.get(key));
		}*/
		/*if (eth.isBroadcast() || eth.isMulticast()) {
			// handle ARP for VIP
			if (pkt instanceof ARP) {
				// retrieve arp to determine target IP address
				ARP arpRequest = (ARP) eth.getPayload();
				byte[] mac = sw.getPort(OFPort.OFPP_LOCAL.getValue()).getHardwareAddress();
				System.out.printf("LOCAL PORT MAC = %X:%X:%X:%X:%X:%X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

				
			}
		}*/
		/*IPacket arpReply = new Ethernet()
        .setSourceMACAddress(mac_src)
        .setDestinationMACAddress(eth.getSourceMACAddress())
        .setEtherType(Ethernet.TYPE_ARP)
        .setVlanID(eth.getVlanID())
        .setPriorityCode(eth.getPriorityCode())
        .setPayload(
            new ARP()
            .setHardwareType(ARP.HW_TYPE_ETHERNET)
            .setProtocolType(ARP.PROTO_TYPE_IP)
            .setHardwareAddressLength((byte) 6)
            .setProtocolAddressLength((byte) 4)
            .setOpCode(ARP.OP_REPLY)
            .setSenderHardwareAddress(mac_src)
            .setSenderProtocolAddress(IPv4.toIPv4Address(((InetSocketAddress)sw.getInetAddress()).getAddress().getHostAddress()))
            .setTargetHardwareAddress(eth.getSourceMACAddress())
            .setTargetProtocolAddress(IPv4.toIPv4Address(((InetSocketAddress)sw.getInetAddress()).getAddress().getHostAddress()))
            );*/
		/*byte[] raw_data = "abcdefg".getBytes();
		
		IPacket udp_data = new Data().deserialize(raw_data, 0, raw_data.length);
		
		UDP udp_packet = new UDP();
		udp_packet.setDestinationPort((short)5134);
		udp_packet.setSourcePort((short)4321);
		udp_packet.setPayload(udp_data);
		
		IPv4 ip_packet = new IPv4();
		ip_packet.setDestinationAddress("255.255.255.255");
		ip_packet.setSourceAddress("0.0.0.0");
		ip_packet.setTtl((byte) 64);
		ip_packet.setProtocol(IPv4.PROTOCOL_UDP);
		ip_packet.setPayload(udp_packet);
		
		Ethernet eth_packet = new Ethernet();
		eth_packet.setDestinationMACAddress(mac);
		eth_packet.setSourceMACAddress(mac_src);
		eth_packet.setEtherType(Ethernet.TYPE_IPv4);
		eth_packet.setPayload(ip_packet);
		
		pushPacket(eth_packet, sw, OFPacketOut.BUFFER_ID_NONE, OFPort.OFPP_NONE.getValue(),
                OFPort.OFPP_LOCAL.getValue(), cntx, true);*/
		return Command.CONTINUE;
	}
	/**
     * used to push any packet - borrowed routine from Forwarding
     * 
     * @param OFPacketIn pi
     * @param IOFSwitch sw
     * @param int bufferId
     * @param short inPort
     * @param short outPort
     * @param FloodlightContext cntx
     * @param boolean flush
     */    
    public void pushPacket(IPacket packet, 
                           IOFSwitch sw,
                           int bufferId,
                           short inPort,
                           short outPort, 
                           FloodlightContext cntx,
                           boolean flush) {
        if (log.isTraceEnabled()) {
            log.trace("PacketOut srcSwitch={} inPort={} outPort={}", 
                      new Object[] {sw, inPort, outPort});
        }

        OFPacketOut po =
                (OFPacketOut) floodlightProvider.getOFMessageFactory()
                                                .getMessage(OFType.PACKET_OUT);

        // set actions
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(new OFActionOutput(outPort, (short) 0xffff));

        po.setActions(actions)
          .setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);
        short poLength =
                (short) (po.getActionsLength() + OFPacketOut.MINIMUM_LENGTH);

        // set buffer_id, in_port
        po.setBufferId(bufferId);
        po.setInPort(inPort);

        // set data - only if buffer_id == -1
        if (po.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            if (packet == null) {
                log.error("BufferId is not set and packet data is null. " +
                          "Cannot send packetOut. " +
                        "srcSwitch={} inPort={} outPort={}",
                        new Object[] {sw, inPort, outPort});
                return;
            }
            byte[] packetData = packet.serialize();
            poLength += packetData.length;
            po.setPacketData(packetData);
        }

        po.setLength(poLength);

        try {
            counterStore.updatePktOutFMCounterStoreLocal(sw, po);
            messageDamper.write(sw, po, null, flush);
        } catch (IOException e) {
            log.error("Failure writing packet out", e);
        }
    }

	@Override
	public Ovsp_setup setupServerMirror(IOFSwitch sw, byte hostType,
			setupHost conf) {
		byte[] mac_src = {0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00};
		byte[] mac = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
		System.out.printf("LOCAL PORT MAC = %X:%X:%X:%X:%X:%X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		System.out.printf("LOCAL PORT IP = %s\n", ((InetSocketAddress)sw.getInetAddress()).getAddress().getHostAddress());
		
		//byte[] raw_data = "abcdefg".getBytes();
		
		Ovsp_setup setup = new Ovsp_setup(hostType, conf);
		byte[] raw_data = setup.toByte();
		
		IPacket udp_data = new Data().deserialize(raw_data, 0, raw_data.length);
		
		UDP udp_packet = new UDP();
		udp_packet.setDestinationPort((short)18591);
		udp_packet.setSourcePort((short)4321);
		udp_packet.setPayload(udp_data);
		
		IPv4 ip_packet = new IPv4();
		ip_packet.setDestinationAddress("255.255.255.255");
		ip_packet.setSourceAddress("0.0.0.0");
		ip_packet.setTtl((byte) 64);
		ip_packet.setProtocol(IPv4.PROTOCOL_UDP);
		ip_packet.setPayload(udp_packet);
		
		Ethernet eth_packet = new Ethernet();
		eth_packet.setDestinationMACAddress(mac);
		eth_packet.setSourceMACAddress(mac_src);
		eth_packet.setEtherType(Ethernet.TYPE_IPv4);
		eth_packet.setPayload(ip_packet);

		pushPacket(eth_packet, sw, OFPacketOut.BUFFER_ID_NONE, OFPort.OFPP_NONE.getValue(),
                OFPort.OFPP_LOCAL.getValue(), null, true);
		return setup;
	}
}
