package burp;

import java.io.PrintWriter;
import py4j.GatewayServer;

public class BurpExtender implements IBurpExtender {
    
    	@Override
	public void registerExtenderCallbacks (IBurpExtenderCallbacks callbacks)
	{
            callbacks.setExtensionName("Burp Python Gateway");

            PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
            
            GatewayServer gatewayServer = new GatewayServer(callbacks);
            gatewayServer.start();
            
            callbacks.registerExtensionStateListener(new ExtensionStateListener(gatewayServer));
            
            stdout.println("Burp Python Gateway Loaded!");
	}
}
