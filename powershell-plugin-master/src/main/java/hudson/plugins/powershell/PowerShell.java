package hudson.plugins.powershell;

import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.tasks.CommandInterpreter;
import org.apache.commons.lang.SystemUtils;
import org.kohsuke.stapler.DataBoundConstructor;

/**
# "{\"settingsName\":\"Default\", \"overrides\":{\"scanName\":\"PLSWORK!\", \"startUrls\":[\"http://zero.webappsecurity.com/\"],\"scanScope\":\"self\", \"scopedPaths\":[\"/\",\"/login.html\"]}}"

# Valid Scans
# "settingsName":"Default", "overrides":{"scanName":"PLSWORK!", "startUrls":["http://zero.webappsecurity.com/"],"scanScope":"self", "scopedPaths":["/","/login.html"]}
# "settingsName":"Default", "overrides":{"scanName":"PLSWORK!", "startUrls":["http://zero.webappsecurity.com/"]}

$JSON = @'
{
 "settingsName":"Default", "overrides":{"scanName":"PLSWORK!", "startUrls":["http://zero.webappsecurity.com/"],"scanScope":"self", "scopedPaths":["/","/login.html"]}
}
'@


Invoke-RestMethod -Uri http://EC2AMAZ-468247R:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body $JSON
 */
public class PowerShell extends CommandInterpreter {
	
	private final String settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode;
	private final String ipInstance;
	private int scanPort;
	
	
    @DataBoundConstructor
    public PowerShell(String ipInstance, int scanPort, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) { 
    	super(intializeCommand(ipInstance, scanPort, settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode));
    	this.ipInstance = ipInstance;
    	this.scanPort = scanPort;
    	this.settingsName = settingsName;
    	this.scanName = scanName;
    	this.startUrls = startUrls;
    	this.crawlAuditMode = crawlAuditMode;
    	this.sharedThreads = sharedThreads;
    	this.crawlThreads = crawlThreads;
    	this.auditThreads = auditThreads;
    	this.startOption = startOption;
    	this.loginMacro = loginMacro;
    	this.workFlowMacros = workFlowMacros;
    	this.tcMarcoParameters = tcMarcoParameters;
    	this.smartCredentials = smartCredentials;
    	this.networkCredentials = networkCredentials;
    	this.networkAuthenticationMode = networkAuthenticationMode;
    	this.allowedHosts = allowedHosts;
    	this.policyID = policyID;
    	this.checkIDs = checkIDs;
    	this.dontStartScan = dontStartScan;
    	this.scanScope = scanScope;
    	this.scopedPaths = scopedPaths;
    	this.clientCertification = clientCertification;
    	this.storeName = storeName;
    	this.isGlobal = isGlobal;
    	this.serialNumber = serialNumber;
    	this.bytes = bytes;
    	this.reuseScan = reuseScan;
    	this.scanId = scanId;
    	this.mode = mode;
    }

    protected String getFileExtension() {
        return ".ps1";
    }
    
    
    /* Function: intializeCommand
     * 
     * Purpose: This function will extract all the input fields the user has given relating to a desired scan
     * then build a string based on the information. After this, our string is sent to the super method
     * from Jenkin's core: command interpreter.
     */
    public static String intializeCommand(String ipInstance, int scanPort, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {  	
    	// Invoke-RestMethod -Uri http://localhost:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body '{ "settingsName": "Default" }'
    	// Remember to check and sanitize.
    	// Assert scan port is a number and a valid port.
    	
    	
    	// Default Scan:
    	// Invoke-RestMethod -Uri http://localhost:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body '{ "settingsName": "Default" }'
    	
    	// return "Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans -Method Post -ContentType 'application/json' ";
    	return "Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans";
    }
    

    public String[] buildCommandLine(FilePath script) {
        if (isRunningOnWindows(script)) {
            return new String[] { "powershell.exe", "-NonInteractive", "-ExecutionPolicy", "Bypass", "& \'" + script.getRemote() + "\'"};
        } else {
            // ExecutionPolicy option does not work (and is not required) for non-Windows platforms
            // See https://github.com/PowerShell/PowerShell/issues/2742
            return new String[] { "pwsh", "-NonInteractive", "& \'" + script.getRemote() + "\'"};
        }
    }

    protected String getContents() {
        return command + "\r\nexit $LastExitCode";
    }

    private boolean isRunningOnWindows(FilePath script) {
        // Ideally this would use a property of the build/run, but unfortunately CommandInterpreter only gives us the
        // FilePath, so we need to guess based on that.
        if (!script.isRemote()) {
            // Running locally, so we can just check the local OS
            return SystemUtils.IS_OS_WINDOWS;
        }

        // Running remotely, guess based on the path. A path starting with something like "C:\" is Windows.
        String path = script.getRemote();
        return path.length() > 3 && path.charAt(1) == ':' && path.charAt(2) == '\\';
    }
    
    

    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @Override
        public String getHelpFile() {
            return "/plugin/powershell/help.html";
        }
        
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }

        public String getDisplayName() {
            return "Can Custom WI Plug-In";
        }
    }
    
    
// Jenkins saves text field input for jobs through getters.
// IE: If you were put in text in a input box, save the job, and come back then the text will still be there.
//************************************** GETTERS  *******************************//
    
    public String getipInstance() {
    	return ipInstance;
    }
    
    public int getScanPort() {
    	return scanPort;
    }
    
    public String getSettingsName() {
    	return settingsName;
    }
    
    public String getScanName() {
    	return scanName;
    }
    
    public String getStartUrls() {
    	return startUrls;
    }
    
    public String getCrawlAuditMode() {
    	return crawlAuditMode;
    }
    
    public String getSharedThreads() {
    	return sharedThreads;
    }
    
    public String getCrawlThreads() {
    	return crawlThreads;
    }
    
    public String getAuditThreads() {
    	return auditThreads;
    }
    
    public String getStartOption() {
    	return startOption;
    }
    
    public String getLoginMacro() {
    	return loginMacro;
    }
    
    public String getWorkFlowMacros() {
    	return workFlowMacros;
    }
    
    public String getTcMacroParameters() {
    	return tcMarcoParameters;
    }
    
    public String getSmartCredentials() {
    	return smartCredentials;
    }
    
    public String getNetworkCredentials() {
    	return networkCredentials;
    }
    
    public String getNetworkAuthenticationMode() {
    	return networkAuthenticationMode;
    }
    
    
    
 //*****************************************************************************************//
    
    
    
    
    /*
         this.allowedHosts = allowedHosts;
         this.policyID = policyID;
         this.checkIDs = checkIDs;
         this.dontStartScan = dontStartScan;
         this.scanScope = scanScope;
         this.scopedPaths = scopedPaths;
         this.clientCertification = clientCertification;
         this.storeName = storeName;
         this.isGlobal = isGlobal;
         this.serialNumber = serialNumber;
         this.bytes = bytes;
         this.reuseScan = reuseScan;
         this.scanId = scanId;
         this.mode = mode;*/
    
    
    
}
