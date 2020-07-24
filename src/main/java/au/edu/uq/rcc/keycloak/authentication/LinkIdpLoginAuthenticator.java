package au.edu.uq.rcc.keycloak.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * @author Hoang Nguyen
 */
public class LinkIdpLoginAuthenticator extends AbstractIdpAuthenticator {
    
	private DirContext ctx = null;
	private static Logger logger = Logger.getLogger(LinkIdpLoginAuthenticator.class);
	
    protected String getUsername(AuthenticationFlowContext context,
    		BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }
    
    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            UserModel existingUser = context.getSession().users().getUserByEmail(brokerContext.getEmail(), context.getRealm());
            if (existingUser != null) {
                return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }
    
    

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
	protected void actionImpl(AuthenticationFlowContext context, 
			SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {		
	}


	@Override
	protected void authenticateImpl(AuthenticationFlowContext context, 
			SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
		if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
            context.attempted();
            return;
        }

        String username = getUsername(context, brokerContext);
        if (username == null) {
            context.getAuthenticationSession().setAuthNote(ENFORCE_UPDATE_PROFILE, "true");
            context.resetFlow();
            return;
        }

        ExistingUserInfo duplication = checkExistingUser(context, username, serializedCtx, brokerContext);

        if (duplication == null) {
        	System.out.println(">>>>>>>>>>User does not exist. New user is not being created.");
        	context.failure(AuthenticationFlowError.UNKNOWN_USER);
        } else {
            // Set duplicated user, so next authenticators can deal with it
            context.getAuthenticationSession().setAuthNote(EXISTING_USER_INFO, duplication.serialize());
            UserModel existingUser = context.getSession().users().getUserByEmail(brokerContext.getEmail(), context.getRealm());
            String baseDn = context.getAuthenticatorConfig().getConfig().get(LinkIdpLoginAuthenticatorFactory.LDAP_SECURITY_BASE_DN);
            try {
        		List<String> clusters = getClusterAccess(context, baseDn, existingUser.getUsername());
        		System.out.println(">>>>>>>>>>>>>[LinkIdpLoginAuthneticator]clusters:" + clusters.toString());
        		existingUser.setAttribute("clusters", clusters);
				context.setUser(existingUser);
	        	context.success();
			} catch (NamingException e) {
				System.out.println("Internal error:" + e.getMessage());
				context.failure(AuthenticationFlowError.INTERNAL_ERROR);        
			}
            
            context.setUser(existingUser);
            context.success();
        }
		
	}
    
    
    private List<String> getClusterAccess(AuthenticationFlowContext context, 
    		String baseDn, String username) 
    		throws NamingException {
    	String clusterNamesStr = context.getAuthenticatorConfig().getConfig().get(LinkIdpLoginAuthenticatorFactory.CLUSTER_NAMES);
		String[] clusterNames = clusterNamesStr.split(";");
        List<String> clusters = new ArrayList<String>(Arrays.asList(clusterNames));
        if(this.ctx == null)
    		this.initLdapContext(context);
		String searchFilter = String.format("(cn=%s)", escapeLDAPSearchFilter(username));
		NamingEnumeration<SearchResult> results = 
				ctx.search(baseDn, searchFilter, new SearchControls());
		while(results.hasMore()) {
			SearchResult result = results.next();
			String dn = result.getAttributes().get("dn").toString();
			for(String name: clusterNames) {
				if(dn.contains(name))
					clusters.add(name);
			}
		}
		return clusters;
    }
    
    /**
     * create ldap context
     * @param context
     * @throws NamingException
     */
    private void initLdapContext(AuthenticationFlowContext context) throws NamingException{
    	AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    	String ldapProviderUrl = config.getConfig().get(LinkIdpLoginAuthenticatorFactory.LDAP_SERVER_URL);
    	String ldapSecurityPrinciple = config.getConfig().get(LinkIdpLoginAuthenticatorFactory.LDAP_SECURITY_PRINCIPLE);
    	String ldapSecurityAuthentication= config.getConfig().get(LinkIdpLoginAuthenticatorFactory.LDAP_SECURITY_AUTHENTICATION);
    	String ldapSecurityCredentials= config.getConfig().get(LinkIdpLoginAuthenticatorFactory.LDAP_SECURITY_CREDENTIALS);
    	
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, ldapProviderUrl);

		// Authenticate if credentials were provided
		if (ldapSecurityPrinciple != null) {
			env.put(Context.SECURITY_AUTHENTICATION, ldapSecurityAuthentication);
			env.put(Context.SECURITY_PRINCIPAL, ldapSecurityPrinciple);
			env.put(Context.SECURITY_CREDENTIALS, ldapSecurityCredentials);
		}
		else
			throw new NamingException("Ldap Principle must not be null");
		ctx = new InitialDirContext(env);
	}
    
    /**
	 * Prevent LDAP injection
	 * @param filter LDAP filter string to escape
	 * @return escaped string
	 */
	private String escapeLDAPSearchFilter(String filter) {
	       StringBuilder sb = new StringBuilder();
	       for (int i = 0; i < filter.length(); i++) {
	           char curChar = filter.charAt(i);
	           switch (curChar) {
	               case '\\':
	                   sb.append("\\5c");
	                   break;
	               case '*':
	                   sb.append("\\2a");
	                   break;
	               case '(':
	                   sb.append("\\28");
	                   break;
	               case ')':
	                   sb.append("\\29");
	                   break;
	               case '\u0000':
	                   sb.append("\\00");
	                   break;
	               default:
	                   sb.append(curChar);
	           }
	       }
	       return sb.toString();
	}
	
}
