package com.enzoic.auth.nodes;

import static com.enzoic.auth.Constants.ERROR_OUTCOME;
import static com.enzoic.auth.Constants.FALSE_OUTCOME;
import static com.enzoic.auth.Constants.OLD_PASSWORD;
import static com.enzoic.auth.Constants.TRUE_OUTCOME;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.security.PrivilegedAction;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import com.iplanet.dpro.session.SessionID;
import org.forgerock.am.identity.persistence.IdentityStore;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.idrepo.ldap.IdentityNotFoundException;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdType;



/**
 * @author Sacumen (www.sacumen.com)
 * Enzoic Save Password Node with true and false outcome.
 * Saves new password to Identity Repository.
 */
@Node.Metadata(outcomeProvider = EnzoicSaveNewPassword.EnzoicSavePasswordOutcomeProvider.class,
        configClass = EnzoicSaveNewPassword.Config.class, tags = {"marketplace"})
public class EnzoicSaveNewPassword implements Node {

    public static final String BUNDLE = "com/enzoic/auth/nodes/EnzoicSaveNewPassword";
    private final CoreWrapper coreWrapper;

    private final Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider;
    private final Logger logger = LoggerFactory.getLogger(EnzoicSaveNewPassword.class);
    private static final String loggerPrefix = "[Enzoic Save Password][Marketplace] ";


    /**
     * Configuration for the data store node.
     */
    public interface Config {
    }

    @Inject
    public EnzoicSaveNewPassword(CoreWrapper coreWrapper, Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider) {
        this.coreWrapper = coreWrapper;

        this.adminTokenActionProvider = adminTokenActionProvider;
    }

    /**
     * Execution of the node starts from here.
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        NodeState sharedState = context.getStateFor(this);

        try {
            logger.debug(loggerPrefix + "Started");

            updatePassword(context);
            IdentityStore idrepo = coreWrapper.getIdentityRepository(coreWrapper.convertRealmPathToRealmDn(sharedState.get(REALM).asString()));
            logger.info("AMIdentityRepository claimed");

            NameCallback nameCallback = new NameCallback("notused");
            nameCallback.setName(sharedState.get(USERNAME).asString());

            PasswordCallback passwordCallback = new PasswordCallback("notused", false);
            passwordCallback.setPassword(getPassword(context));

            logger.info("NameCallback and PasswordCallback set");

            Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};

            boolean success = false;

            try {
                logger.debug("authenticating {} " + nameCallback.getName());
                success = idrepo.authenticate(getIdentityType(), callbacks)
                        && isActive(context, nameCallback);
                logger.debug("Success is " + success);
            } catch (InvalidPasswordException e) {
                logger.error("invalid password error");
            } catch (IdentityNotFoundException e) {
                logger.error("invalid username error");
            } catch (IdRepoException | AuthLoginException e) {
                logger.error("Exception in data store decision node");
                throw new NodeProcessException(e);
            } catch (SSOException e) {
                logger.error("Exception checking user status");
                throw new NodeProcessException(e);
            }

            return Action.goTo(String.valueOf(success)).build();
        } catch (Exception e) {
            logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
            logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
            e.printStackTrace();
            context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ":" + e.getMessage());
            return Action.goTo(EnzoicSavePasswordOutcomes.ERROR.name()).build();
        }
    }

    /**
     * @param context      TreeContext
     * @param nameCallback NameCallback
     * @return True if user is active else false.
     * @throws IdRepoException
     * @throws SSOException
     */
    private boolean isActive(TreeContext context, NameCallback nameCallback) throws IdRepoException, SSOException {

        NodeState sharedState = context.getStateFor(this);
        AMIdentity userIdentity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(sharedState.get(USERNAME).asString(), coreWrapper.convertRealmPathToRealmDn(sharedState.get(REALM).asString()));
        return userIdentity.isActive();
    }

    /**
     * @return IdType
     */
    private IdType getIdentityType() {
        return IdType.USER;
    }


    /**
     * @param context TreeContext
     * @return Getting password from transient state.
     * @throws NodeProcessException
     */
    private char[] getPassword(TreeContext context) throws NodeProcessException {
        String password = context.transientState.get(PASSWORD).asString();
        if (password == null) {
            logger.error("Password is null, note this field is not stored across multiple requests");
            throw new NodeProcessException("Unable to authenticate");
        }
        return password.toCharArray();
    }

    private void updatePassword(TreeContext context) throws NodeProcessException {
        logger.info("{} updating password....", loggerPrefix);

        String userName = context.sharedState.get(USERNAME).asString();
        String oldPassword = context.sharedState.get(OLD_PASSWORD).asString();
        String newPassword = context.transientState.get(PASSWORD).asString();

        try {
            logger.debug("{} Request ID -> {}", loggerPrefix, context.request);

            AMIdentity identity =  new AMIdentity(SSOTokenManager.getInstance().createSSOToken(context.request.ssoTokenId));

            logger.debug("{} Identity -> {}", loggerPrefix, identity);

            identity.changePassword(oldPassword,newPassword);

        } catch (SSOException | IdRepoException e) {
            throw new NodeProcessException(e.getLocalizedMessage());
        }
    }

    public enum EnzoicSavePasswordOutcomes {
        TRUE("True"),
        FALSE("False"),
        ERROR("Error");
        private final String outcomeErrorAction;
        EnzoicSavePasswordOutcomes(String pOutcomeErrorAction) {
            this.outcomeErrorAction = pOutcomeErrorAction;
        }

        @Override
        public String toString(){
            return outcomeErrorAction;
        }
    }

    /**
     * Defines the possible outcomes from this ThreatMetrix Session Query Node.
     */
    public static class EnzoicSavePasswordOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                    EnzoicSaveNewPassword.class
                            .getClassLoader());
            return ImmutableList.of(
                    new Outcome(EnzoicSavePasswordOutcomes.TRUE.name(), bundle.getString(TRUE_OUTCOME)),
                    new Outcome(EnzoicSavePasswordOutcomes.FALSE.name(), bundle.getString(FALSE_OUTCOME)),
                    new Outcome(EnzoicSavePasswordOutcomes.ERROR.name(), bundle.getString(ERROR_OUTCOME)));
        }
    }
}
