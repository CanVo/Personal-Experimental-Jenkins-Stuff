package io.jenkins.plugins.sample;

//Test
import PowerShell.java

import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

public class HelloWorldBuilder extends Builder implements SimpleBuildStep {

    private final String name;
    
    private final String settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParameters, smartCredentials, networkCredentials, networkAuthenticationMode, allowedHosts, policyID, checkIDs, dontStartScan, scanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode;
    
    private boolean useFrench;

    @DataBoundConstructor
    public HelloWorldBuilder(String name, String secretcode, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParameters, String smartCredentials, String networkCredentials, String networkAuthenticationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String scanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {
        this.name = name;
        
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
        
        PowerShell shellCommand = new PowerShell("Test");
    }

    public String getName() {
        return name;
    }

    public boolean isUseFrench() {
        return useFrench;
    }

    @DataBoundSetter
    public void setUseFrench(boolean useFrench) {
        this.useFrench = useFrench;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {
        if (useFrench) {
            listener.getLogger().println("Bonjour, " + name + "!");
        } else {
            listener.getLogger().println("Hello, " + name + "!");
        }
    }
    
    
    
    
    
    
    

    @Symbol("greet")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public FormValidation doCheckName(@QueryParameter String value, @QueryParameter boolean useFrench)
                throws IOException, ServletException {
            if (value.length() == 0)
                return FormValidation.error(Messages.HelloWorldBuilder_DescriptorImpl_errors_missingName());
            if (value.length() < 4)
                return FormValidation.warning(Messages.HelloWorldBuilder_DescriptorImpl_warnings_tooShort());
            if (!useFrench && value.matches(".*[éáàç].*")) {
                return FormValidation.warning(Messages.HelloWorldBuilder_DescriptorImpl_warnings_reallyFrench());
            }
            return FormValidation.ok();
        }
        
        
        // Test to see if the settings name field is empty
        public FormValidation doCheckSettingsName(@QueryParameter String settingsName) {
        	if (settingsName.length() == 0)
                return FormValidation.error(Messages.HelloWorldBuilder_DescriptorImpl_errors_missingSettingsFile());
        	
        	return FormValidation.ok();
        }
        
        
        
        
        
        
        
        
        // isApplicable and getDisplayName is auto generated.
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }
        
        // Build step name for plugin.
        @Override
        public String getDisplayName() {
            return Messages.HelloWorldBuilder_DescriptorImpl_DisplayName();
        }

    }

}
