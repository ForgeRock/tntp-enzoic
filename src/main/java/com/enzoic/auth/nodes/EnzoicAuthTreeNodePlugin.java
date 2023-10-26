/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2018 ForgeRock AS.
 */

package com.enzoic.auth.nodes;

import static java.util.Arrays.asList;
import java.util.Map;
import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;

import com.google.common.collect.ImmutableMap;


public class EnzoicAuthTreeNodePlugin extends AbstractNodeAmPlugin {

	static private String currentVersion = "1.0.4";
	public static final   String logAppender    = "[Version: " + currentVersion + "][Marketplace] ";

	@Override
	protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
		return ImmutableMap.of(
				EnzoicAuthTreeNodePlugin.currentVersion, asList(
						EnzoicCheckPassword.class
				));
	}

	@Override
	public void onInstall() throws PluginException {
		super.onInstall();
	}


	@Override
	public void onStartup() throws PluginException {
		super.onStartup();
	}

	@Override
	public void upgrade(String fromVersion) throws PluginException {
		pluginTools.upgradeAuthNode(EnzoicCheckPassword.class);
		super.upgrade(fromVersion);
	}

	@Override
	public String getPluginVersion() {
		return EnzoicAuthTreeNodePlugin.currentVersion;
	}
}
