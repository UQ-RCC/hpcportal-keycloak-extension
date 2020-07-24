package au.org.rcc.keycloak.authentication;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;
import java.util.ArrayList;

/**
 * @author Hoang Nguyen
 */
public class LinkIdpOnlyAuthenticator extends AbstractIdpAuthenticator {
	private static Logger logger = Logger.getLogger(LinkIdpOnlyAuthenticator.class);
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

        String username = getUsername(context, serializedCtx, brokerContext);
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
            context.setUser(existingUser);
            context.success();
        }
		
	}
	
    // Could be overriden to detect duplication based on other criterias (firstName, lastName, ...)
    // this is a hack
    protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username, 
                    SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
        if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
            String userEmail = brokerContext.getEmail();
            String[] institutions = {"imb"};
            List<String> emailsToTry = new ArrayList<String>();
            emailsToTry.add(userEmail);
            for(String inst: institutions)
                emailsToTry.add(userEmail.split("@", 0)+ "@" + inst + "." +  userEmail.split("@", 1));
            // go through it
            for(String mail: emailsToTry){
                UserModel existingUser = context.getSession().users().getUserByEmail(mail, context.getRealm());
                // check it is the same user --> this is weak
                if (existingUser != null) {
                    return new ExistingUserInfo(existingUser.getId(), UserModel.EMAIL, existingUser.getEmail());
                }
            }
        }

        UserModel existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
        if (existingUser != null) {
            return new ExistingUserInfo(existingUser.getId(), UserModel.USERNAME, existingUser.getUsername());
        }

        return null;
    }

    protected String getUsername(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, 
                                                                            BrokeredIdentityContext brokerContext) {
        RealmModel realm = context.getRealm();
        return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
    }
    
    
}
