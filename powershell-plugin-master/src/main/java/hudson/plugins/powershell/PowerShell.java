package hudson.plugins.powershell;

import java.util.regex.Pattern;
import hudson.Extension;
import hudson.FilePath;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.tasks.CommandInterpreter;
import hudson.util.FormValidation;
import org.apache.commons.lang.SystemUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import java.util.List;
import java.util.Arrays;

public class PowerShell extends CommandInterpreter {
	
	private int scanPort;
	private static int errorCase = 0;	// Check for overflows + injection with special chars.
	private String ipInstance, settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode;
	private static String [] overrideScanParamStrings = {"scanName", "startUrls", "crawlAuditMode", "sharedThreads", "crawlThreads", "auditThreads", "startOption", "loginMacro", "workFlowMacros", "tcMarcoParameters", "smartCredentials", "networkCredentials", "networkAuthenticationMode", "allowedHosts", "policyID", "checkIDs", "dontStartScan", "scanScope", "scopedPaths", "clientCertification", "storeName", "isGlobal", "serialNumber", "bytes", "reuseScan", "scanId", "mode"};
	// startUrls, WorkFlowMacros, SmartCredentials, networkCredentials, Allowed Hosts, CheckIDs, scopedPaths, 
	private static List boxedScanParamStrings = Arrays.asList("startUrls", "workFlowMacros", "smartCredentials", "networkCredentials", "allowedHosts", "checkIDs", "scopedPaths");
	
	
    @DataBoundConstructor
    public PowerShell(String ipInstance, int scanPort, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) { 
    	super(intializeCommand(ipInstance, scanPort, settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode));
    	
    	//********** Mandatory Parameters ****************************//
    	this.ipInstance = ipInstance;
    	this.scanPort = scanPort;
    	this.settingsName = settingsName;
    	//********** SCAN CASE 1: REQUIRES OVERRIDE STRING ***********//
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
    	//********** SCAN CASE 2: REQUIRES REUSE SCAN STRING **********//
    	this.reuseScan = reuseScan;
    	this.scanId = scanId;
    	this.mode = mode;
    }
    
    

    /*
     * Function: getFileExtension
     * 
     * Purpose: Inherited from powershell plugin.
     */
    protected String getFileExtension() {
        return ".ps1";
    }
    
    
    
    /*
     * Function: buildCommandLine
     * 
     * Purpose: Inherited from powershell plugin.
     */
    public String[] buildCommandLine(FilePath script) {
        if (isRunningOnWindows(script)) {
            return new String[] { "powershell.exe", "-NonInteractive", "-ExecutionPolicy", "Bypass", "& \'" + script.getRemote() + "\'"};
        } else {
            // ExecutionPolicy option does not work (and is not required) for non-Windows platforms
            // See https://github.com/PowerShell/PowerShell/issues/2742
            return new String[] { "pwsh", "-NonInteractive", "& \'" + script.getRemote() + "\'"};
        }
    }

    
    
    /*
     * Function: getContents
     * 
     * Purpose: Inherited from powershell plugin.
     */
    protected String getContents() {
        return command + "\r\nexit $LastExitCode";
    }

    
    
    /*
     * Function: isRunningOnWindows
     * 
     * Purpose: Inherited from powershell plugin.
     */
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
    
    
    
    /* Function: intializeCommand
     * 
     * Purpose: This function will extract all the input fields the user has given relating to a desired scan
     * 			then build a string based on the information. After this, our string is sent to the super method
     * 			from Jenkin's core: command interpreter.
     */
    public static String intializeCommand(String ipInstance, int scanPort, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {  	
    	// Invoke-RestMethod -Uri http://localhost:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body '{ "settingsName": "Default" }'
    	// Remember to check and sanitize.
    	
    	// Default Scan:
    	// Invoke-RestMethod -Uri http://localhost:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body '{ "settingsName": "Default" }'
    	//String memes =  "\'{\"settingsName\":\"" + settingsName + "\", \"overrides\":{\"scanName\":\"" + scanName + "\"}}\'";
    	//return "Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body " + memes;
    	
    	
    	/************************* SCAN CASE 1: API Scan call includes override parameters ********************
    	* Description: In this scan case, the user will be utilizing some parameters that require a specific call to the API.
    	* 				That specific call consists of utilizing the "override" segment with the included parameters. If that
    	* 				is the case, then we make sure we build our scan string with the "overrides" portion present.
    	* 
    	* Example Scan With ADVANCED OVERRIDE PARAMETERS:
    	* curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{ "settingsName": "Default", "overrides": { "startUrls": ["http://myhost/appPath/"], "scanScope": "self", "scopedPaths": ["/appPath/","/appPath/level1/"] } }' http://localhost:8083/webinspect/scanner/scans
    	***************************************************************************************************/
    	
    	// I declare my array here now because at this point, my scan parameter variables should be populated and ready to go after the constructor sets them.
    	String[] overrideVars = {scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes};
    	for (int i = 0; i < overrideVars.length; i++) {
    		// I check for length 0 string or null because the options that are shown on the page but are not filled in equate to something that is NOT "" but length of 0.
    		// The options that are not shown (haven't checked in advanced options box) AND are not filled in equate to null. 
    		// Logic: As soon as I find an override parameter, automatically construct an override scan string.
    		if (overrideVars[i] != null && overrideVars[i].length() != 0) {
    			return overrideStringBuild(ipInstance, scanPort, settingsName, overrideVars);
    		}
    	}

    	/************************* SCAN CASE 2: API Scan call is utilizing reuse scan parameter *****************
    	*Description: In this scan case, the user will be utilizing the reuse scan parameter. For this case,
    	* 				the scan call will be using an exisiting scan as the baseline and overrides can be specified if desired.
    	* 				
    	* 				*** IMPORTANT NOTE: If this is the case, then settingsName will be ignored for the overrides.
    	* 
    	* Example Scan with REUSE PARAMETERS:
    	* curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{ "reuseScan":{"scanId":"98451e29-8209-4286-a9dc-b686c64fc30c","mode":"Incremental"} }' http://localhost:8083/webinspect/scanner/scans
    	* 
    	*******************************************************************************************************/
    	return "Write-Host *reuse scan call*";
    	
    	
    	/************************* SCAN CASE 3: API Scan call is just using base default parameters *****************
    	 * Description: In this scan case, the user will be utilizing just base default parameters that are required and
    	 * 				omitting the special case parameters (reuse and overrides).
    	 * 
    	 * Example Scan With Default Parameters And No Override Parameters:
    	 * curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{ "settingsName": "Default" }' http://localhost:8083/webinspect/scanner/scans
    	 ************************************************************************************************************/
    	//return "Write-Host Yelp!";
    	
    	//return "Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans";	
    }
    
    
    /* Function: overrideStringBuild
     * 
     * Purpose: Will construct the powershell scan string that consists of the powershell API call
     * 			with provided scan parameters from the user.
     * 			
     */
    public static String overrideStringBuild(String ipInstance, int scanPort, String settingsName, String[] overrideVars) {
    	//TODO:
    	// * MAKE SURE TO SANITIZE FOR SKETCHY INPUT. IF I SEE A SEMICOLON? RETURN NOTHING!
    	// * ACCOUNT FOR MULTIPLE VALUES FOR START URL CSV STYLE.
    	// * ACCOUNT FOR BRACKETS.
    	
    	// Loop to (Length - 3) because we are not accounting for the reuse params. That is a special case.
    	String scan = "{ ";
    	for (int i = 0; i < overrideVars.length - 3; i++) {
    		// Account for null. If the parameter value is null, the value for that paramter will be "".
    		// Important because API call doesn't take "null" but can take empty spaces to indicate no value.
    		if (overrideVars[i] == null) {
    			//scan += "\"" + overrideScanParamStrings[i] + "\":\"\", ";
    			scan += overrideStringBuildHelper(overrideScanParamStrings[i], "");
    		} else {
    			//scan += "\"" + overrideScanParamStrings[i] + "\":\"" + overrideVars[i] +"\", ";
    			scan += overrideStringBuildHelper(overrideScanParamStrings[i], overrideVars[i]);
    		}
    	}
    	
    	// If check to ensure that the ending string format is correct for a proper scan initialization.
    	if (scan.endsWith(", ")) {
    		scan = scan.substring(0,scan.length() - 2) + " }";
    	} else {
    		scan += "}";
    	}
    	
    	// Default Scan:
    	// Invoke-RestMethod -Uri http://localhost:8083/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body '{ "settingsName": "Default" }'
    	//return "Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body " + memes;
    	String scanInvoke = "Write-Host Invoke-RestMethod -Uri http://" + ipInstance + ":" + scanPort + "/webinspect/scanner/scans -Method Post -ContentType 'application/json' -Body \'{ \"settingsName\":\"" + settingsName + "\", \"overrides\":" + scan + "\'";
    	//String scanInvoke = "Write-Host \'" + scan + " \'";
    	return scanInvoke;
    }
    
    /*
     * Function overrideStringBuildHelper
     * 
     * Purpose: Will provide assistance for the scan string concatenation/build for our scans based on
     * 			provided parameter values. Will make it efficient to check if some of the values utilize
     * 			a box parameter format:
     * 	
     * Example:
     * 			{"scanName":""}
    			{"startUrls": ["string"]}
     * 
     * Parameters: 
     * > String overrideVarName: This is the literal string for the parameter name we're filling in.
     * > String overrideVarValue: This is the value that was entered by the user from the Jenkins job page.
     */
    
    public static String overrideStringBuildHelper(String overrideVarName, String overrideVarValue) {
    	// Check if it's a box utilizing val.
    	// Check if it's comma seperated
    	// Maybe account for thread ints without the "".
    	// 
    	
    	String builtString;
    	
    	
    	// Example: - overrideVarName = scanName
    	//			- overrideVarValue = My First Scan
    	//
    	// 			builtString = "scanName":"My First Scan"
    	if (boxedScanParamStrings.contains(overrideVarName)){
    		builtString = "\"" + overrideVarName + "\": [\"" + overrideVarValue +"\"], ";
    	}
    	else {
    		builtString = "\"" + overrideVarName + "\":\"" + overrideVarValue +"\", ";
    	}
    	
    	return builtString;
    }
    
    
    
    public static String errorCases(){
    	
    	switch (errorCase) {
    		case 1:
    			break;
    		case 2:
    			break;
    		case 3:
    			break;
    	}
    	
    	return "henlo friends! :^)";
    	
    }

    
    
    
    //********************************** DESCRIPTOR SEGMENT **********************************//
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        @Override
        public String getHelpFile() {
            return "/plugin/powershell/help.html";
        }
        
        
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }
        
        
        
        /* Function: getDisplayName
         * 
         * Purpose: Returns the display name of the plugin. 
         * 			The name will be displayed to the user when choosing a build step in the drop down menu in Jenkins.
         */
        public String getDisplayName() {
            return "W.I. Create Scan";
            // return "W.I. Create Scan and Wait Until Finish";
        }
        
        
        
        /* Function: doCheckIpInstance
         * 
         * Purpose: Checks user input for the name of the settings file.
         * 			Test to see if the settings name field is empty and if the user has entered bad chars.
         * 			This is important so we can avoid command injection if the user were to utilize chars like ";" or encoded characters.
         */
        public FormValidation doCheckIpInstance(@QueryParameter String ipInstance) {
        	if (ipInstance.length() == 0)
                return FormValidation.error("Please input an ip address or host name of the W.I. instance");
        	if (!(ipInstance.matches("^[a-zA-Z0-9./:,-]*$")))
        		return FormValidation.error("Input not valid! Provided input may have prohibted characters!");
        	
        	return FormValidation.ok();
        }
        
        
        
        /* Function: doCheckSettingsName
         * 
         * Purpose: Checks user input for the name of the settings file.
         * 			Test to see if the settings name field is empty and if the user has entered bad chars.
         * 			This is important so we can avoid command injection if the user were to utilize chars like ";" or encoded characters.
         */
        public FormValidation doCheckSettingsName(@QueryParameter String settingsName) {
        	if (settingsName.length() == 0)
                return FormValidation.error("Please input the name of the settings file that will be used for the scan.");
        	if (!(settingsName.matches("^[a-zA-Z0-9./:,-]*$")))
        		return FormValidation.error("Input not valid! Provided input may have prohibted characters!");
        	
        	return FormValidation.ok();
        }
        
        
        
        /* Function: doCheckStartUrls
         * 
         * Purpose: Check user input for their start urls. Tests to see if user has entered bad chars.
         * 			This is important so we can avoid command injection if the user were to utilize chars like ";" or encoded characters.
         */
        public FormValidation doCheckStartUrls(@QueryParameter String startUrls) {
        	// Check if the given String contains any prohibited chars that aren't alphanumeric chars + some special chars.
        	if (!(startUrls.matches("^[a-zA-Z0-9./:,-]*$")))
        		return FormValidation.error("Input not valid! Provided input may have prohibted characters!");
        	
        	return FormValidation.ok();
        }
    }
    
    
    
// Jenkins saves jelly text field input from jobs through getters.
// IE: If you were put in text to an input box, save the job, and come back then the text will still be there.
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
    
    public String gettcMarcoParameters() {
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
    
    public String getAllowedHosts() {
    	return allowedHosts;
    }
    
    public String getPolicyID() {
    	return policyID;
    }
    
    public String getCheckIDs() {
    	return checkIDs;
    }
    
    public String getDontStartScan() {
    	return dontStartScan;
    }
    
    public String getScanScope() {
    	return scanScope;
    }
    
    public String getScopedPaths() {
    	return scopedPaths;
    }
    
    public String getClientCertification() {
    	return clientCertification;
    }
    
    public String getStoreName() {
    	return storeName;
    }
    
    public String getIsGlobal() {
    	return isGlobal;
    }
    
    public String getSerialNumber() {
    	return serialNumber;
    }
    
    public String getBytes() {
    	return bytes;
    }
    
    public String getReuseScan() {
    	return reuseScan;
    }
    
    public String getScanId() {
    	return scanId;
    }
    
    public String getMode() {
    	return mode;
    }
    
 //*****************************************************************************************//
    
}
