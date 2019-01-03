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
	
    @DataBoundConstructor
    //public PowerShell(String command, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {
    public PowerShell(String command, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) { 
    	super(intializeCommand(settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode));
    	//super(command);
        
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
    
    
    // ******************** TEST FUNCTION *********************** //
    public static String intializeCommand(String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {
    	
    	return "Write-Host HelloWorld!";
    	
    }
    // ********************************************************** //

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
}
