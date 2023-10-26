package com.enzoic.auth.nodes;

import static javax.security.auth.callback.TextOutputCallback.ERROR;
import static javax.security.auth.callback.TextOutputCallback.WARNING;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.PASSWORD;
import static org.forgerock.openam.utils.CollectionUtils.isEmpty;
import static com.enzoic.auth.Constants.*;

import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextOutputCallback;

/**
 *
 * @author Sacumen(www.sacumen.com)
 *
 * A node that prompt the user to reset a password.
 *
 * Enzoic Reset Password node with single outcome. It takes new password and confirm password from the user.
 *
 * Outcome is connected to Enzoic Check Password node.
 *
 */
@Node.Metadata(outcomeProvider = EnzoicResetPassword.EnzoicResetPasswordOutcomeProvider.class,
        configClass = EnzoicResetPassword.Config.class, tags = {"marketplace"})
public class EnzoicResetPassword implements Node {
    private final Logger logger = LoggerFactory.getLogger(EnzoicResetPassword.class);
    public static final String BUNDLE = "com/enzoic/auth/nodes/EnzoicResetPassword";
    private static final String loggerPrefix = "[Enzoic Reset Password][Marketplace] ";
    private final Config config;


    private ResourceBundle bundle;

    /**
     * Node configuration.
     */
    public interface Config {

        /**
         * The length of the password.
         *
         * @return the length
         */
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default int minPasswordLength() {
            return 8;
        }
    }

    /**
     * Constructor.
     *
     * @param config the config
     */
    @Inject
    public EnzoicResetPassword(@Assisted EnzoicResetPassword.Config config) {
        this.config = config;
    }

    /**
     * Execution of the node starts from here.
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        NodeState sharedState = context.getStateFor(this);

        List<Callback> passwordCallbacks = new ArrayList<>();

        try {
            logger.debug(loggerPrefix + "Started");

            bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
            logger.debug("{} After Bundle", loggerPrefix);
            logger.debug("{} Bundle -> {}", loggerPrefix, bundle);
            if(!context.getCallback(PasswordCallback.class).isPresent()) {
                passwordCallbacks = initialiseCallbacks(context);
            }
            logger.debug("{} passwordCallbacks -> {}", loggerPrefix, passwordCallbacks);
            List<PasswordCallback> callbacks = context.getCallbacks(PasswordCallback.class);
            logger.debug(loggerPrefix + " Callbacks -> {} ", callbacks);
            if (isEmpty(callbacks)) {
                logger.debug(loggerPrefix + " Callbacks is empty.");
                return send(passwordCallbacks).build();
            }
            PasswordPair passwords = getPasswords(callbacks);
            logger.debug("{} Check Password -> {}", loggerPrefix, checkPassword(passwords));
            if (passwords.password.length() < config.minPasswordLength()) {
                passwordCallbacks.add(0,getErrorCallback(String.format(bundle.getString("error.password.length"),config.minPasswordLength())));

            } else if (!passwords.password.equals(passwords.confirmPassword)) {
                passwordCallbacks.add(0,getErrorCallback(bundle.getString("error.password.mismatch")));
            }
            if (!checkPassword(passwords)) {
                return send(passwordCallbacks).build();
            }
            sharedState.putTransient(PASSWORD, passwords.password);
            logger.debug("{} After Setting Transient State", loggerPrefix);

            return Action.goTo(EnzoicResetPasswordOutcomes.NEXT.name()).build();
        } catch (Exception e) {
            logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
            logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
            e.printStackTrace();
            context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ":" + e.getMessage());
            return Action.goTo(EnzoicResetPasswordOutcomes.ERROR.name()).build();
        }
    }

    /**
     * Initialize the password callbacks for new and confirm password.
     */
    private List initialiseCallbacks(TreeContext context) {

        logger.debug("{} Into InitialiseCallbacks", loggerPrefix);

        NodeState sharedState = context.getStateFor(this);

        List<Callback> passwordCallbacks = new ArrayList<>();

        JsonValue resetPasswordMsg = sharedState.get(RESET_PASSWORD);
        logger.info("Reset password message is "+ resetPasswordMsg);

        if(!resetPasswordMsg.isNull())
            passwordCallbacks.add(new TextOutputCallback(WARNING,resetPasswordMsg.asString()));

        passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.password"), false));
        passwordCallbacks.add(new PasswordCallback(bundle.getString("callback.password.confirm"), false));

        return passwordCallbacks;
    }

    /**
     * Retrieving new password and confirm password.
     * @param callbacks Password Callbacks
     * @return Passwords
     * @throws NodeProcessException
     */
    private PasswordPair getPasswords(List<PasswordCallback> callbacks) throws NodeProcessException {
        List<String> passwords = callbacks.stream()
                .map(PasswordCallback::getPassword)
                .map(String::new)
                .collect(Collectors.toList());

        if (passwords.size() != 2) {
            throw new NodeProcessException("There should be 2 PasswordCallback and " + passwords.size()
                    + " has been found");
        }
        return new PasswordPair(passwords.get(0), passwords.get(1));
    }

    /**
     * Checks minimum length of the passwords, passwords should be equal and they should not be empty as well.
     *
     * @param passwords New and Confirm passsword.
     * @return true if passwords are valid.
     */
    private boolean checkPassword(PasswordPair passwords) {

        logger.debug("{} Into Check Password", loggerPrefix);

        if (StringUtils.isBlank(passwords.password)) {
            return false;
        } else if (passwords.password.length() < config.minPasswordLength()) {
            return false;
        } else if (!passwords.password.equals(passwords.confirmPassword)) {
            return false;
        }
        return true;
    }

    /**
     * Showing error message to user.
     * @param message Message
     * @return TextOutputCallback
     */
    private TextOutputCallback getErrorCallback(String message) {
        return new TextOutputCallback(ERROR, message);
    }


    private static class PasswordPair {
        final String password;
        final String confirmPassword;

        PasswordPair(String password, String confirmPassword) {
            this.password = password;
            this.confirmPassword = confirmPassword;
        }
    }

    public enum EnzoicResetPasswordOutcomes {
        NEXT("Next"),
        ERROR("Error");
        private final String outcomeErrorAction;
        EnzoicResetPasswordOutcomes(String pOutcomeErrorAction) {
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
    public static class EnzoicResetPasswordOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                    EnzoicResetPassword.class
                            .getClassLoader());
            return ImmutableList.of(
                    new Outcome(EnzoicResetPasswordOutcomes.NEXT.name(), bundle.getString(NEXT_OUTCOME)),
                    new Outcome(EnzoicResetPasswordOutcomes.ERROR.name(), bundle.getString(ERROR_OUTCOME)));
        }
    }
}
