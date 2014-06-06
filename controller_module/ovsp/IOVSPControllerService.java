package net.floodlightcontroller.ovsp;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface IOVSPControllerService extends IFloodlightService {
	public Ovsp_setup setupServerMirror(IOFSwitch sw, byte hostType, setupHost conf);
}
