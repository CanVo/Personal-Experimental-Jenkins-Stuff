package io.jenkins.plugins.sample;

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
    private final String secretcode;
    
    private final String settingsName, scanName, startUrls, crawlAuditMode, sharedThreads, crawlThreads, auditThreads, startOption, loginMacro, workFlowMacros, tcMarcoParamters, smartCredentials, networkCredentials, networkAuthenicationMode, allowedHosts, policyID, checkIDs, dontStartScan, cscanScope, scopedPaths, clientCertification, storeName, isGlobal, serialNumber, bytes, reuseScan, scanId, mode;
    
    
    private boolean useFrench;

    @DataBoundConstructor
    public HelloWorldBuilder(String name, String secretcode, String settingsName, String scanName, String startUrls, String crawlAuditMode, String sharedThreads, String crawlThreads, String auditThreads, String startOption, String loginMacro, String workFlowMacros, String tcMarcoParamters, String smartCredentials, String networkCredentials, String networkAuthenicationMode, String allowedHosts, String policyID, String checkIDs, String dontStartScan, String cscanScope, String scopedPaths, String clientCertification, String storeName, String isGlobal, String serialNumber, String bytes, String reuseScan, String scanId, String mode) {
        this.name = name;
        this.secretcode = secretcode;
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

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.HelloWorldBuilder_DescriptorImpl_DisplayName();
        }

    }

}
