package com.enzoic.auth.nodes;

import static com.enzoic.auth.Constants.*;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.security.PrivilegedAction;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import com.enzoic.auth.FetchCompromisedPasswordFromLocalCSVFile;
import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.enzoic.auth.CheckCompromisedCredentialsUsingAPI;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;

/**
 *
 * @author Saucmen(www.sacumen.com) Enzoic Check Compromised Password node with
 *         two outcome. If entered password or credentials is compromised then
 *         true outcome and it will go to Enzoic Reset Password node. If entered
 *         password or credentials is not compromised then false outcome and it
 *         will go to Success Page.
 *
 */
@Node.Metadata(outcomeProvider = EnzoicCheckPassword.EnzoicCheckPasswordOutcomeProvider.class, configClass = EnzoicCheckPassword.Config.class, tags = {"marketplace"})
public class EnzoicCheckPassword implements Node {
	private static final String BUNDLE = "com/enzoic/auth/nodes/EnzoicCheckPassword";
	private final Logger logger = LoggerFactory.getLogger(EnzoicCheckPassword.class);
	private static final String loggerPrefix = "[Enzoic Check Compromised Password]" + EnzoicAuthTreeNodePlugin.logAppender;
	private CheckCompromisedCredentialsUsingAPI checkCompromisedCredentialsUsingAPI;
	private final Config config;
	private final Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider;
	private final CoreWrapper coreWrapper;

	/**
	 * Configuration for the data store node.
	 */
	public interface Config {

		@Attribute(order = 100, requiredValue = true)
		String Api_Key();

		@Attribute(order = 200, requiredValue = true)
		@Password
		char[] Secret();

		@Attribute(order = 300)
		default boolean CheckForSynchronousOrAsynchronousFlow() {
			return false;
		}

		@Attribute(order = 400, requiredValue = true)
		Integer CredentialCheckTimeout();

		@Attribute(order = 500, requiredValue = true)
		String UserAttribute();

		@Attribute(order = 600)
		String UniqueIdentifier();

		@Attribute(order = 700, requiredValue = true)
		String LocalPasswordFilePath();

		@Attribute(order = 800, requiredValue = true)
		default int LocalPasswordCacheExpirationTime() {
			return 3;
		}

		@Attribute(order = 900)
		default CheckCompromisedPassword CheckCompromisedPasswordOptions() {
			return CheckCompromisedPassword.LocalPasswordCheck;
		}
	}

	public enum CheckCompromisedPassword {
		LocalPasswordCheck,
		PasswordCheckUsingAPI,
		CredentialCheckUsingAPI

	}

	/**
	 * Inject dependency
	 *
	 * @param config                              EnzoicCheckPassword Config
	 * @param checkCompromisedCredentialsUsingAPI CheckCompromisedCredentialsUsingAPI
	 */
	@Inject
	public EnzoicCheckPassword(@Assisted Config config, CheckCompromisedCredentialsUsingAPI checkCompromisedCredentialsUsingAPI, CoreWrapper coreWrapper, Provider<PrivilegedAction<SSOToken>> adminTokenActionProvider) {
		this.config = config;
		this.checkCompromisedCredentialsUsingAPI = checkCompromisedCredentialsUsingAPI;
		this.adminTokenActionProvider = adminTokenActionProvider;
		this.coreWrapper = coreWrapper;
	}

	/**
	 * Execution of the node starts from here.
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {

		NodeState sharedState = context.getStateFor(this);
		try {
			logger.debug(loggerPrefix + "Started");
			checkCompromisedCredentialsUsingAPI.initialize(config.Api_Key(), String.valueOf(config.Secret()),
					config.CredentialCheckTimeout());
			String password = sharedState.get(SharedStateConstants.PASSWORD).asString();
			String userName = sharedState.get(SharedStateConstants.USERNAME).asString();
			if (config.CheckForSynchronousOrAsynchronousFlow()) {
				AsyncThread thread = new AsyncThread(userName, password, context);
				thread.start();
				return Action.goTo(EnzoicCheckPasswordOutcomes.FALSE.name()).build();
			} else {
				boolean result = processPassword(userName, password,context);
				logger.debug("Result from synchronous process is " + result);
				if (result) {
					logger.debug(loggerPrefix + " Into the Result True Block");
					sharedState.putTransient(RESET_PASSWORD, RESET_PASSWORD_MSG);
					logger.debug(loggerPrefix + " After setting Transient");
					JsonValue oldPasswordValue = sharedState.get(OLD_PASSWORD);

					if(oldPasswordValue == null || oldPasswordValue.isNull() || oldPasswordValue.toString().equalsIgnoreCase("null")){
						logger.debug(loggerPrefix + "Into Null Condition ");
						sharedState.putShared(OLD_PASSWORD, password);
					}
				}
				logger.debug(loggerPrefix + "Result -> " + String.valueOf(result).toUpperCase());
				return Action.goTo(String.valueOf(result).toUpperCase()).build();
			}
		} catch (Exception e) {
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
			e.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ":" + e.getMessage());
			return Action.goTo(EnzoicCheckPasswordOutcomes.ERROR.name()).build();
		}
	}

	/**
	 * Stores result in Identity Store
	 *
	 * @param result
	 * @param context
	 */
	private void storeAttributeInIdentityStore(Boolean result, TreeContext context) {
		logger.info("Storing result into identity store");

		NodeState sharedState = context.getStateFor(this);
		Map<String, Set<String>> attrMap = new HashMap<>();
		Set<String> resultSet = new HashSet<>();
		resultSet.add(String.valueOf(result));
		attrMap.put(config.UserAttribute(), resultSet);
		try {
			AMIdentity identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(sharedState.get(USERNAME).asString(), coreWrapper.convertRealmPathToRealmDn(sharedState.get(REALM).asString()));

			identity.setAttributes(attrMap);
			identity.store();
		} catch (Exception e) {
			logger.error("Not able to store attribute in identity store. " + e);

			logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
			e.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());
		}
	}

	/**
	 * Get value from Identity Store
	 *
	 * @param uniqueIdentifier
	 * @param context
	 */
	private String getAttributeFromIdentityStore(String uniqueIdentifier,TreeContext context) throws NodeProcessException {
		logger.info("Storing result into identity store");
		NodeState sharedState = context.getStateFor(this);
		Set<String> attributes;
		try {
			AMIdentity identity = coreWrapper.getIdentityOrElseSearchUsingAuthNUserAlias(sharedState.get(USERNAME).asString(), coreWrapper.convertRealmPathToRealmDn(sharedState.get(REALM).asString()));

			attributes = identity.getAttribute(uniqueIdentifier);
		} catch (Exception e) {
			logger.error("Not able to get attribute from identity store. " + e);

			logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
			e.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());

			return new String();
		}
		Iterator<String> iterator = attributes.iterator();
		if(iterator.hasNext()){
			return iterator.next();
		} else{
			return StringUtils.EMPTY;
		}
	}

	/**
	 * Processing request
	 *
	 * @param userName UserName
	 * @param password UserPassword
	 * @return result
	 */
	private Boolean processPassword(String userName, String password, TreeContext context) throws NodeProcessException {
		try {
			return processPasswordCheck(userName, password, context);
		} catch (NodeProcessException e) {
			logger.error("Caught exception, Not able to process", e);
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
			logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
			e.printStackTrace();
			context.getStateFor(this).putShared(loggerPrefix + "Exception", new Date() + ": " + e.getMessage());

			throw e;
		}

	}

	/**
	 * Checking if password is compromised or not.
	 *
	 * @param userName UserName
	 * @param password UserPassword
	 * @return result
	 * @throws NodeProcessException
	 */
	private boolean processPasswordCheck(String userName, String password, TreeContext context) throws NodeProcessException {
		String configValue = config.CheckCompromisedPasswordOptions().toString();
		if (configValue.equals(LOCAL_PASSWORD_CHECK)) {
			logger.debug("Checking compromised password using local file system");
			logger.debug("Cache expiration time is " + config.LocalPasswordCacheExpirationTime());
			logger.debug("Config file is " + config.LocalPasswordFilePath());

			FetchCompromisedPasswordFromLocalCSVFile compromisedPasswordFromLocalCsvFile = FetchCompromisedPasswordFromLocalCSVFile
					.getInstance(this.config.LocalPasswordCacheExpirationTime(), this.config.LocalPasswordFilePath());

			List<String> compromisedPasswords = compromisedPasswordFromLocalCsvFile.getEntry(userName);

			return compromisedPasswords.contains(password);
		} else if (configValue.equals(PASSWORD_CHECK_USING_API)) {
			logger.debug("Checking compromised password using API");

			return checkCompromisedCredentialsUsingAPI.passwordCheckUsingAPI(password);
		} else if (configValue.equals(CREDENTIAL_CHECK_USING_API)) {
			logger.debug("Checking compromised credentials using API");
			String uniqueIdentifier = config.UniqueIdentifier();

			if(uniqueIdentifier != null && !uniqueIdentifier.isEmpty()){
				String attributeValue = getAttributeFromIdentityStore(uniqueIdentifier,context);
				if(attributeValue.isEmpty()){
					throw new NodeProcessException("Not able to get any value of "+uniqueIdentifier+" from identity store");
				}else{
					userName = attributeValue;
				}
			}

			return checkCompromisedCredentialsUsingAPI.credentialCheckUsingAPI(userName, password);

		} else {
			throw new NodeProcessException(NO_CONFIGURATION_ERROR_MSG);
		}
	}

	public class AsyncThread extends Thread {

		private String userName;
		private String password;
		private TreeContext context;

		AsyncThread(String userName, String password, TreeContext context) {
			this.userName = userName;
			this.password = password;
			this.context = context;
		}

		public void run() {
			logger.info(this.getName() + ": Async Thread is running...");
			Boolean result = null;
			try {
				result = processPassword(userName, password,context);
			} catch (NodeProcessException e) {
				logger.error("Caught exception while checking password", e);

				logger.error("{} Exception occurred: {}", loggerPrefix, e.getMessage());
				logger.error("{} Exception occurred: {}", loggerPrefix, e.getStackTrace());
				e.printStackTrace();
			}
			logger.info("Result from Asynchronous process is " + result);
			storeAttributeInIdentityStore(result, context);
		}
	}

	public enum EnzoicCheckPasswordOutcomes {
		TRUE("True"),
		FALSE("False"),
		ERROR("Error");
		private final String outcomeErrorAction;
		EnzoicCheckPasswordOutcomes(String pOutcomeErrorAction) {
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
	public static class EnzoicCheckPasswordOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
					EnzoicCheckPassword.class
							.getClassLoader());
			return ImmutableList.of(
					new Outcome(EnzoicCheckPasswordOutcomes.TRUE.name(), bundle.getString(TRUE_OUTCOME)),
					new Outcome(EnzoicCheckPasswordOutcomes.FALSE.name(), bundle.getString(FALSE_OUTCOME)),
					new Outcome(EnzoicCheckPasswordOutcomes.ERROR.name(), bundle.getString(ERROR_OUTCOME)));
		}
	}
}
