package au.org.coesra.keycloak.authentication;

import java.util.List;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;

import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * @author Hoang Nguyen
 */
public class LinkIdpLoginAuthenticator implements Authenticator {
    
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Auto-linking IdP login to federated identity.");        
        UserModel existingUser = AbstractIdpAuthenticator.getExistingUser(
                context.getSession(), context.getRealm(), context.getAuthenticationSession());
        if(existingUser != null)
        {
        	Map<String, List<String>> attributesMap = existingUser.getAttributes();
        	context.setUser(existingUser);
        	context.success();
        }
        else
        	context.failure(AuthenticationFlowError.UNKNOWN_USER);         
    }

    public void action(AuthenticationFlowContext context) {

    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    public void close() {

    }
}
