package au.edu.uq.rcc.keycloak.authentication;

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

public final class LinkIdpUQAuthenticator extends AbstractIdpAuthenticator {
	private static final Logger LOGGER = Logger.getLogger(LinkIdpUQAuthenticator.class);

	@Override
	protected void authenticateImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {
		if (context.getAuthenticationSession().getAuthNote(EXISTING_USER_INFO) != null) {
			context.attempted();
			return;
		}

		String username = brokerContext.getUserAttribute("username");
		if(username == null) {
			context.failure(AuthenticationFlowError.UNKNOWN_USER);
			return;
		}

		/*
		LOGGER.debug("XXXXDUMP:");
		LOGGER.debugf("brokerContext.getUsername() = %s", brokerContext.getUsername());
		LOGGER.debugf("brokerContext.getBrokerSessionId() = %s", brokerContext.getBrokerSessionId());
		LOGGER.debugf("brokerContext.getBrokerUserId() = %s", brokerContext.getBrokerUserId());
		LOGGER.debugf("brokerContext.getCode() = %s", brokerContext.getCode());
		LOGGER.debugf("brokerContext.getEmail() = %s", brokerContext.getEmail());
		LOGGER.debugf("brokerContext.getFirstName() = %s", brokerContext.getFirstName());
		LOGGER.debugf("brokerContext.getLastName() = %s", brokerContext.getLastName());
		LOGGER.debugf("brokerContext.getId() = %s", brokerContext.getId());
		LOGGER.debugf("brokerContext.getModelUsername() = %s", brokerContext.getModelUsername());
		LOGGER.debugf("brokerContext.getToken() = %s", brokerContext.getToken());
		LOGGER.debugf("brokerContext.getUserAttribute(\"uid\") = %s", brokerContext.getUserAttribute("uid"));
		LOGGER.debugf("brokerContext.getUserAttribute(\"sn\") = %s", brokerContext.getUserAttribute("sn"));
		LOGGER.debugf("brokerContext.getUserAttribute(\"cn\") = %s", brokerContext.getUserAttribute("cn"));
		LOGGER.debugf("brokerContext.getUserAttribute(\"mail\") = %s", brokerContext.getUserAttribute("mail"));
		LOGGER.debugf("brokerContext.getUserAttribute(\"employeeType\") = %s", brokerContext.getUserAttribute("employeeType"));
		LOGGER.debugf("brokerContext.getUserAttribute(\"firstName\") = %s", brokerContext.getUserAttribute("firstName"));

		brokerContext.getContextData().forEach((k, v) -> {
			LOGGER.debugf("brokerContext.getContextData(\"%s\") = %s", k, v);
		});

		LOGGER.debugf("serializedCtx.getUsername() = %s", serializedCtx.getUsername());
		LOGGER.debugf("serializedCtx.getBrokerSessionId() = %s", serializedCtx.getBrokerSessionId());
		LOGGER.debugf("serializedCtx.getBrokerUserId() = %s", serializedCtx.getBrokerUserId());
		LOGGER.debugf("serializedCtx.getCode() = %s", serializedCtx.getCode());
		LOGGER.debugf("serializedCtx.getEmail() = %s", serializedCtx.getEmail());
		LOGGER.debugf("serializedCtx.getFirstName() = %s", serializedCtx.getFirstName());
		LOGGER.debugf("serializedCtx.getLastName() = %s", serializedCtx.getLastName());
		LOGGER.debugf("serializedCtx.getId() = %s", serializedCtx.getId());
		LOGGER.debugf("serializedCtx.getModelUsername() = %s", serializedCtx.getModelUsername());
		LOGGER.debugf("serializedCtx.getToken() = %s", serializedCtx.getToken());
		LOGGER.debugf("serializedCtx.getIdentityProviderId() = %s", serializedCtx.getIdentityProviderId());
		serializedCtx.getAttributes().forEach((k, v) -> {
			LOGGER.debugf("serializedCtx.getAttribute(\"%s\") = %s", k, v);
		});
		*/

		UserModel user = context.getSession().users().getUserByUsername(username, context.getRealm());
		if(user == null) {
			context.failure(AuthenticationFlowError.UNKNOWN_USER);
			return;
		}

		context.getAuthenticationSession().setAuthNote(
				EXISTING_USER_INFO,
				new ExistingUserInfo(user.getId(), UserModel.USERNAME, username).serialize()
		);
		context.setUser(user);
		context.success();
	}

	@Override
	protected void actionImpl(AuthenticationFlowContext context, SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

	}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}
}
