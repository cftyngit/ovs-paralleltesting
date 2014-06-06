package net.floodlightcontroller.ovsp;

import java.io.IOException;

import net.floodlightcontroller.packet.IPv4;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class OVSPSetupSerializer  extends JsonSerializer<Ovsp_setup>{

	@Override
	public void serialize(Ovsp_setup setup, JsonGenerator jGen, SerializerProvider serializer) 
			throws IOException, JsonProcessingException {
		jGen.writeStartObject();
        
		String hostType;
		System.out.printf("serialize HostType = %s\n", setup.getHostType());
		if(setup.getHostType() == Ovsp_setup.HOST_SERVER)
			hostType = "server";
		else
			hostType = "mirror";
		
        jGen.writeStringField("host type", hostType);
        jGen.writeStringField("MAC address", setup.getHostConf().getHostMac().toString());
        jGen.writeStringField("IP address", IPv4.fromIPv4Address(setup.getHostConf().getHostIP()));
        

        jGen.writeEndObject();
	}

}
