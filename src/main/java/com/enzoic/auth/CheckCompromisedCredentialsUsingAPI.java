package com.enzoic.auth;

import java.io.IOException;

import com.enzoic.auth.nodes.EnzoicAuthTreeNodePlugin;
import com.enzoic.client.Enzoic;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class CheckCompromisedCredentialsUsingAPI {

	private static final String loggerPrefix = "[CheckCompromisedCredentialsUsingAPI]" + EnzoicAuthTreeNodePlugin.logAppender;

	private Enzoic enzoic;
	private final static Logger logger = LoggerFactory.getLogger(CheckCompromisedCredentialsUsingAPI.class);


	public void initialize(String apiKey, String secret, Integer timeoutInMs) {
		logger.debug(loggerPrefix + "Into initializing the Enzoic Class!!");
		logger.debug(loggerPrefix + "Timeout In Ms -> " + timeoutInMs);
		this.enzoic = new Enzoic(apiKey, secret);
		this.enzoic.SetRequestTimeout(timeoutInMs);
	}


	public boolean passwordCheckUsingAPI(String password) throws NodeProcessException {
		logger.info("passwordCheckUsingAPI....");

		try {
			return enzoic.CheckPassword(password);
		}
		catch (IOException e) {
			logger.error("Caught some error while checking compromised password using API");
			throw new NodeProcessException(e.getLocalizedMessage());
		}
	}

	public boolean credentialCheckUsingAPI(String userName,String password) throws NodeProcessException {
		logger.info("credentialCheckUsingAPI....");

		try {
			return enzoic.CheckCredentials(userName,password);
		} catch (IOException e) {
			logger.error("Caught some error while checking compromised credentials using API");
			throw new NodeProcessException(e.getLocalizedMessage());
		}
	}

}