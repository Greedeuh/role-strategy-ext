package jenkins.plugins.rolestrategyext.rolestrategyext;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedMap;
import java.util.regex.Pattern;

import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import com.michelin.cio.hudson.plugins.rolestrategy.Role;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;

import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.RootAction;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import jenkins.model.Jenkins;

@Extension 
public class MyRootAction implements RootAction {
	
	private RoleBasedAuthorizationStrategy strat;
	private StaplerRequest req;
	private StaplerResponse rsp;
	
    @Override 
    public String getIconFileName() { 
        return "document.png"; 
    } 

    @Override 
    public String getDisplayName() { 
        return "My Root Action"; 
    } 

    @Override 
    public String getUrlName() { 
        return "role-strategy-ext"; 
    }
    
    public void doGetSidAssignedRoles(StaplerRequest req, StaplerResponse rsp, @QueryParameter(required = true) String sid) throws IOException { 
    	
    	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
    	
    	this.req = req;
    	this.rsp = rsp;
    	
    	AuthorizationStrategy strat = Jenkins.getInstance().getAuthorizationStrategy();
    	
    	if(strat instanceof RoleBasedAuthorizationStrategy) {
    		
    		this.strat = (RoleBasedAuthorizationStrategy) strat;
    		
    		Set<Role> roles = this.getUserRoles(sid);
    		
    		this.printRoles(roles);
    		
    	}else {
    		rsp.sendError(500, "You shall use Role Based Authorization Strategy Plugin.");
    	}
    	
    	
    }
    
    private Set<Role> getUserRoles(String sid){

    	//this.print("Start");

    	Set<Role> sidRoles = new HashSet<Role>();
		RoleBasedAuthorizationStrategy roleStrat = (RoleBasedAuthorizationStrategy) strat;
		
    	sidRoles.addAll(this.getUserRolesByType(sid, RoleBasedAuthorizationStrategy.GLOBAL));
    	sidRoles.addAll(this.getUserRolesByType(sid, RoleBasedAuthorizationStrategy.PROJECT));
    	sidRoles.addAll(this.getUserRolesByType(sid, RoleBasedAuthorizationStrategy.SLAVE));
    	
    	//this.print("Size :" + sidRoles.size());

    	return sidRoles;
    }
    
    private Set<Role> getUserRolesByType(String sid, String type){

    	//this.print("Type = " + type);
		
    	Set<Role> sidRoles = new HashSet<Role>();
    	SortedMap<Role, Set<String>> grantedRoles = this.strat.getGrantedRoles(type);
		
    	for(SortedMap.Entry<Role, Set<String>> entry : grantedRoles.entrySet()) {
    	
    		//this.print("Role : " + entry.getKey().getName());
			
			for(String sidAssigned : entry.getValue()) {

				//this.print("sidAssigned : " + sidAssigned + " --- sid : " + sid + " --- same : " + (sidAssigned.equals(sid)));

				
				if(sidAssigned.equals(sid)) {
					
					sidRoles.add(entry.getKey());
				}
			}
		}

  		//this.print("Size :" + sidRoles.size());
		//this.print("Fin type = " + type);
		
    	return sidRoles;
    }
    
    private void printRoles(Set<Role> roles) {
    	int index = 1;
    	
    	this.print("[");
	    	for(Role role : roles) {
	    		this.printRole(role);
	    		if(roles.size() != index) {
					this.print(",");
				}
	    		index++;
	    	}
    	this.print("]");
    }
    
    private void printRole(Role role) {

		this.print("{");
				this.print("\"name\" : \"" + role.getName() + "\"" + ",");
				this.print("\"pattern\" : \"" + role.getPattern() + "\"" + ",");
				this.printRolePermissions(role);
			
			
		this.print("}");

    }
    
    private void printRolePermissions(Role role) {
    	Set<Permission> perms = role.getPermissions();
    	int index = 1;
    	
    	this.print(" \"permissions\" : [");
    	
	    	for(Permission perm : perms) {
	    		
				this.print("{");
					this.print("\"id\" : \"" + perm.getId() + "\"" + ",");
					this.print("\"name\" : \"" + perm.name + "\"");				
				this.print("}");
				
				if(perms.size() != index) {
					this.print(",");
				}
				index++;
			}
    	this.print("]");
    }
    
    private void print(String text) {
    	try {
			rsp.getWriter().println(text);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    @RequirePOST()
    public void doUnassignSidRole(StaplerRequest req, StaplerResponse rsp, @QueryParameter(required = true) String sid,@QueryParameter(required = true) String roleName, @QueryParameter(required = true) String type) throws IOException { 
    	
    	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
    	
    	this.req = req;
    	this.rsp = rsp;
    	
    	AuthorizationStrategy strat = Jenkins.getInstance().getAuthorizationStrategy();
    	
    	if(strat instanceof RoleBasedAuthorizationStrategy) {
    		
    		this.strat = (RoleBasedAuthorizationStrategy) strat;
    		
    		SortedMap<Role, Set<String>> grantedRoles = this.strat.getGrantedRoles(type);
    		Set<Role> roles = grantedRoles.keySet();
    		Role role = this.findRoleByName(roleName, roles);
    		Set<String> roleMapping = grantedRoles.get(role);
    		for(String aSid : roleMapping) {
    			if(aSid.equals(sid)) {
    				roleMapping.remove(aSid);
    				break;
    			}
    		}
    		
    		Jenkins.getInstance().save();    		
    		
    	}else {
    		rsp.sendError(500, "You shall use Role Based Authorization Strategy Plugin.");
    	}
    	
    	
    }
    
    private Role findRoleByName(String name, Set<Role> roles) {
    	for(Role role : roles) {
    		if(role.getName().equals(name)) {
    			return role;
    		}
    	}
    	return null;
    }
    
    @RequirePOST()
    public void doUpdateRole(StaplerRequest req, StaplerResponse rsp, @QueryParameter(required = true) String name, @QueryParameter(required = true) String type, @QueryParameter(required = false) String newName, @QueryParameter(required = false) String newPattern) throws IOException, NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException { 
    	
    	Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
    	
    	this.req = req;
    	this.rsp = rsp;
    	
    	AuthorizationStrategy strat = Jenkins.getInstance().getAuthorizationStrategy();
    	
    	if(strat instanceof RoleBasedAuthorizationStrategy) {
    		
    		this.strat = (RoleBasedAuthorizationStrategy) strat;
    		
    		SortedMap<Role, Set<String>> grantedRoles = this.strat.getGrantedRoles(type);
    		Set<Role> roles = grantedRoles.keySet();
    		Role role = this.findRoleByName(name, roles);
    		if(role != null) {
	    		Class roleClass = Role.class;
	    		
	    		if(newPattern != null) {
	    			Field patternField = roleClass.getDeclaredField("pattern");// the pattern field is private like the constructor, we make it public here...
	    			patternField.setAccessible(true);
	    			patternField.set(role, Pattern.compile(newPattern));
	    		}
	    		
	    		if(newName != null) {
	    			Field nameField = roleClass.getDeclaredField("name");// the name field is private too...
	    			nameField.setAccessible(true);
	    			nameField.set(role, newName);
	    		}
	    		
	    		Jenkins.getInstance().save();
	    		this.printRole(role);
	    		
    		}else {
    			rsp.sendError(500, "Unknow role.");
    		}
    		
    	}else {
    		rsp.sendError(500, "You shall use Role Based Authorization Strategy Plugin.");
    	}
    	
    	
    }
} 