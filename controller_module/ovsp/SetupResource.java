package net.floodlightcontroller.ovsp;

import java.io.IOException;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.util.MACAddress;

import org.openflow.util.HexString;
import org.restlet.data.Status;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.Put;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

public class SetupResource extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(SetupResource.class);
	
	@Get("json")
	public int receive() {
		setupHost sh = null;
		int hostTypei = 2;
        /*try {
        	sh = jsonToSetupHost(postData);
        } catch (IOException e) {
            log.error("Could not parse JSON {}", e.getMessage());
        }*/
        
        String hostType = (String) getRequestAttributes().get("host");
        String switchId = (String) getRequestAttributes().get("switch");
        
        System.out.printf("hostType = %s\n", hostType);
        System.out.printf("switchId = %s\n", switchId);
        
		return 123;
	}
	
	@Put
    @Post
	public Ovsp_setup setup(String postData) {
		setupHost sh = null;
		byte hostTypei = 2;
        try {
        	sh = jsonToSetupHost(postData);
        } catch (IOException e) {
        	System.out.println("Could not parse JSON %s" + e.getMessage());
            log.error("Could not parse JSON {}", e.getMessage());
        }
        
        String hostType = (String) getRequestAttributes().get("host");
        
        if (hostType.toLowerCase().equals("server"))
        	hostTypei = Ovsp_setup.HOST_SERVER;
        else
        	hostTypei = Ovsp_setup.HOST_MIRROR;
        
        IOVSPControllerService ovsp = (IOVSPControllerService)getContext().getAttributes().get(IOVSPControllerService.class.getCanonicalName());
        
        String switchId = (String) getRequestAttributes().get("switch");
        try {
            IFloodlightProviderService floodlightProvider =
                    (IFloodlightProviderService)getContext().getAttributes().
                        get(IFloodlightProviderService.class.getCanonicalName());
            long dpid = HexString.toLong(switchId);
            IOFSwitch sw = floodlightProvider.getSwitch(dpid);
            ovsp.setupServerMirror(sw, hostTypei, sh);
        } catch (NumberFormatException e) {
        	System.out.println("Could not decode switch ID = " + switchId);
            log.error("Could not decode switch ID = " + switchId);
            setStatus(Status.CLIENT_ERROR_BAD_REQUEST);
        }
        System.out.printf("hostType = %s\n", hostType);
        System.out.printf("switchId = %s\n", switchId);
		return new Ovsp_setup(hostTypei, sh);
	}

    protected setupHost jsonToSetupHost(String json) throws IOException {
        
        if (json==null) return null;
        
        MappingJsonFactory f = new MappingJsonFactory();
        JsonParser jp;
        setupHost setup = new setupHost();
        
        try {
            jp = f.createJsonParser(json);
        } catch (JsonParseException e) {
            throw new IOException(e);
        }
        
        jp.nextToken();
        if (jp.getCurrentToken() != JsonToken.START_OBJECT) {
            throw new IOException("Expected START_OBJECT");
        }
        
        while (jp.nextToken() != JsonToken.END_OBJECT) {
            if (jp.getCurrentToken() != JsonToken.FIELD_NAME) {
                throw new IOException("Expected FIELD_NAME");
            }
            
            String n = jp.getCurrentName();
            jp.nextToken();
            if (jp.getText().equals("")) 
                continue;
 
            if (n.equals("ip")) {
            	setup.address = IPv4.toIPv4Address(jp.getText());
                continue;
            } 
            if (n.equals("mac")) {
                setup.hostMac = MACAddress.valueOf(jp.getText());
                continue;
            }           
            log.warn("Unrecognized field {} in " +
                    "parsing Vips", 
                    jp.getText());
        }
        jp.close();
        
        return setup;
    }
}
