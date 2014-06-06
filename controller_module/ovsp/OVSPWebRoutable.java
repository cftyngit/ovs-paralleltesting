package net.floodlightcontroller.ovsp;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;
import net.floodlightcontroller.virtualnetwork.NoOp;

public class OVSPWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/setup/", SetupResource.class);
		router.attach("/setup/{switch}/{host}", SetupResource.class);
		router.attachDefault(NoOp.class);
		return router;
	}

	@Override
	public String basePath() {
		return "/ovs_paralleltesting";
	}

}
