package au.edu.uq.rcc.keycloak.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class LinkIdpUQAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    private static final LinkIdpUQAuthenticator INSTANCE = new LinkIdpUQAuthenticator();

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public String getId() {
        return "link-idp-uq";
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "UQ Auth Login";
    }

    @Override
    public String getReferenceCategory() {
        return "UQ Auth Login";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Automatically link a successful UQ IDP login with any existing (or new) KeyCloak or Federated account.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
