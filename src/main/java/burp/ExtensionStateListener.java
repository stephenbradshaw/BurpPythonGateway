package burp;

import py4j.GatewayServer;


public class ExtensionStateListener implements IExtensionStateListener {
    private GatewayServer gatewayServer;
    
    
    public ExtensionStateListener(GatewayServer gatewayServer){
        this.gatewayServer = gatewayServer;
        
    }
    
    @Override 
    public void extensionUnloaded(){
        this.gatewayServer.shutdown();
    }
    
}
