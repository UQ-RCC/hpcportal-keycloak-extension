package au.edu.uq.rcc.keycloak.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Automatically link the logged in account with an existing
 * or newly created user rather than prompting the user.
 *
 * @author Ilya Kogan
 */
public class LinkIdpLoginAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    public static final String PROVIDER_ID = "hpcportal-link-idp";
    private static final LinkIdpLoginAuthenticator SINGLETON = new LinkIdpLoginAuthenticator();
    
    public static final String LDAP_SERVER_URL = "ldap.server.url";
    public static final String LDAP_SECURITY_AUTHENTICATION = "ldap.security.authentication";
    public static final String LDAP_SECURITY_PRINCIPLE = "ldap.security.principle";
    public static final String LDAP_SECURITY_CREDENTIALS = "ldap.security.credentials";
    public static final String LDAP_SECURITY_BASE_DN = "ldap.security.base.dn";
    public static final String CLUSTER_NAMES = "cluster.names";
    
    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    public String getId() {
        return PROVIDER_ID;
    }

    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    public void init(Config.Scope scope) {

    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    public void close() {

    }

    public String getDisplayType() {
        return "HPCPortal IDP Login";
    }

    public String getReferenceCategory() {
        return "HPCPortal IDP Login";
    }

    public boolean isConfigurable() {
        return true;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getHelpText() {
        return "Automatically link a successful IDP login with any existing (or new) KeyCloak or Federated account.";
    }

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    static {
    	//ldap connection url
        ProviderConfigProperty LdapServerProperty;
        LdapServerProperty = new ProviderConfigProperty();
        LdapServerProperty.setName(LDAP_SERVER_URL);
        LdapServerProperty.setLabel("LDAP Server URL");
        LdapServerProperty.setType(ProviderConfigProperty.STRING_TYPE);
        LdapServerProperty.setHelpText("LDAP Server URL");
        configProperties.add(LdapServerProperty);
        //security authentication
        ProviderConfigProperty LdapSecurityAuthentication;
        LdapSecurityAuthentication = new ProviderConfigProperty();
        LdapSecurityAuthentication.setName(LDAP_SECURITY_AUTHENTICATION);
        LdapSecurityAuthentication.setLabel("LDAP Security Authentication");
        LdapSecurityAuthentication.setType(ProviderConfigProperty.STRING_TYPE);
        LdapSecurityAuthentication.setDefaultValue("simple");
        LdapSecurityAuthentication.setHelpText("LDAP Security Authentication");
        configProperties.add(LdapSecurityAuthentication);
        //security principle
        ProviderConfigProperty LdapSecurityPrinciple;
        LdapSecurityPrinciple = new ProviderConfigProperty();
        LdapSecurityPrinciple.setName(LDAP_SECURITY_PRINCIPLE);
        LdapSecurityPrinciple.setLabel("LDAP Security Principle");
        LdapSecurityPrinciple.setType(ProviderConfigProperty.STRING_TYPE);
        LdapSecurityPrinciple.setHelpText("LDAP Security Principle");
        configProperties.add(LdapSecurityPrinciple);
        //security credentials
        ProviderConfigProperty LdapSecurityCredentials;
        LdapSecurityCredentials = new ProviderConfigProperty();
        LdapSecurityCredentials.setName(LDAP_SECURITY_CREDENTIALS);
        LdapSecurityCredentials.setLabel("LDAP Security Credentials");
        LdapSecurityCredentials.setType(ProviderConfigProperty.PASSWORD);
        LdapSecurityCredentials.setHelpText("LDAP Security Credentials");
        configProperties.add(LdapSecurityCredentials);
        //basedn 
        ProviderConfigProperty LdapBaseDN;
        LdapBaseDN = new ProviderConfigProperty();
        LdapBaseDN.setName(LDAP_SECURITY_BASE_DN);
        LdapBaseDN.setLabel("LDAP User Base DN");
        LdapBaseDN.setType(ProviderConfigProperty.STRING_TYPE);
        LdapBaseDN.setHelpText("LDAP User Base DN");
        configProperties.add(LdapBaseDN);
        //clusternames 
        ProviderConfigProperty ClusterNames;
        ClusterNames = new ProviderConfigProperty();
        ClusterNames.setName(CLUSTER_NAMES);
        ClusterNames.setLabel("Cluster names");
        ClusterNames.setType(ProviderConfigProperty.STRING_TYPE);
        ClusterNames.setHelpText("Cluser names - separated by semicolon");
        configProperties.add(ClusterNames);
    }
    
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    
    
}
