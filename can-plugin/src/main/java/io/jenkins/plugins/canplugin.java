import hudson.Extension;
import hudson.tasks.Builder;



/**
 * @author Can
 *
 */

public class canplugin extends Builder {
	
	private long time;
	
	@DataBoundConstructor
	public canplugin (long time) {
		this.time = time;
	}
	
	public long getTime () {
		return time;
	}
	
	public void setTime () {
		this.time = time;
	}
	
	
	@Override
	public boolean perform (Build<?, ?> build, Launcher launcher, Buildlistener listener) throws InterruptedException, IOException {
		listener.getLogger().println("Sleeping for: " + time + " ms.");
		Thread.sleep(time);
		return true;
	}
	 
	 
	 
}
	
	
	


