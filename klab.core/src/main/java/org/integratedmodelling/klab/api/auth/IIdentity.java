/*
 * This file is part of k.LAB.
 * 
 * k.LAB is free software: you can redistribute it and/or modify
 * it under the terms of the Affero GNU General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * A copy of the GNU Affero General Public License is distributed in the root
 * directory of the k.LAB distribution (LICENSE.txt). If this cannot be found 
 * see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) 2007-2018 integratedmodelling.org and any authors mentioned
 * in author tags. All rights reserved.
 */
package org.integratedmodelling.klab.api.auth;

import org.integratedmodelling.klab.api.engine.IEngine;
import org.integratedmodelling.klab.api.observations.IObservation;
import org.integratedmodelling.klab.api.runtime.ISession;
import org.integratedmodelling.klab.api.runtime.monitoring.IMonitor;

/**
 * {@code IIdentity} represents all identities known to the IM semantic web.
 * Since 0.10.0 identities are arranged in a parent/child hierarchy through
 * exposing their parent identity, which is only null in top-level identities,
 * i.e. {@link IPartnerIdentity}. The current identity is carried in the
 * {@link IMonitor} available during all computations. From the current
 * identity, those upstream can be retrieved using the {@code IIdentity} API.
 * Identity objects are passed to the API in lieu of raw authorization tokens,
 * to give uniform access to the privileges, metadata and lineage connected to
 * it.
 * <p>
 * * A certificate defines a 'root' identity: a {@link IPartnerIdentity},
 * {@link INodeIdentity} or {@link IUserIdentity}. Nodes and engines start by
 * reading a certificate, which establishes the [partner, [node and [user]]]
 * identities according to context. Engines create a {@link INetworkSession}
 * upon successful connection to the IM web, and append themselves as a
 * {@link IEngine}, then duplicate the {@link IUser} as the default
 * {@link IEngineUser}, to which they can add others if local authentication is
 * enabled. {@link ISession Sessions} are appended to each IEngineUser,
 * {@link IObservation observations} to sessions and tasks to observations.
 * <p>
 * Identities at certain levels (currently node, user, network session, engine,
 * engine user and session) implement the security principals for the REST API.
 * <p>
 * Identities are arranged as follows:
 *
 * <pre>
 * 	IIdentity (abstract)
 * 		IPartner [top-level: each node is owned by a partner]
 * 			INode [physically a server on the k.LAB network; access point for IUser]
 * 				IUser (authenticated by INode, directly or indirectly)
 * 					INetworkSession
 *              		IEngine (has a IUser (automatically promoted to IEngineUser) but can authenticate others as IEngineUser)
 *              			IEngineUser
 * 								ISession
 * 				     				IObservation
 * 									    ITask
 *                                  IScript
 * </pre>
 *
 * @author Ferd
 * @version $Id: $Id
 */
public abstract interface IIdentity {

	static enum Type {
		/**
		 * Identified by an institutional certificate. Each server has a top-level
		 * partner.
		 */
		IM_PARTNER,

		/**
		 * Identified by a node token, owned by a partner.
		 */
		NODE,

		/**
		 * Identified by a user token authenticated by a server.
		 */
		IM_USER,

		/**
		 * Identified by a network session token owned by a server user.
		 */
		NETWORK_SESSION,

		/**
		 * Identified by an engine token using a user certificate
		 */
		ENGINE,

		/**
		 * Identified by an engine user token released by an engine after
		 * authentication. Default engine user is the server user who owns the engine.
		 */
		ENGINE_USER,

		/**
		 * Identified by a session token owned by an engine user.
		 */
		MODEL_SESSION,

		/**
		 * Identified by an observation token owned by a session.
		 */
		OBSERVATION,

		/**
		 * Identifed by a task token owned by a context observation.
		 */
		TASK,

		/**
		 * A script identity identifies a script (namespace with run/test/observe
		 * annotations or imperative code) running as a task within a session.
		 */
		SCRIPT
	}

	/** Constant <code>TYPE</code> */
	Type TYPE = null;

	/**
	 * Unique ID. When appropriate it corresponds to the authorization token
	 * retrieved upon authentication. Assumed to expire at some sensible point in
	 * time, if stored it should be validated before use and refreshed if necessary.
	 *
	 * @return a token to use as authentication when dealing with the engine.
	 */
	String getId();

	/**
	 * Return the parent identity. Null only in IM_PARTNER identities.
	 *
	 * @return a {@link org.integratedmodelling.klab.api.auth.IIdentity} object.
	 */
	IIdentity getParentIdentity();

	/**
	 * True if the identity is of the passed type.
	 *
	 * @param type
	 *            a {@link org.integratedmodelling.klab.api.auth.IIdentity.Type}
	 *            object.
	 * @return a boolean.
	 */
	boolean is(Type type);

	/**
	 * Get the parent identity of the passed type.
	 *
	 * @param type
	 *            a {@link java.lang.Class} object.
	 * @return the desired identity or null.
	 * @param <T>
	 *            a T object.
	 */
	<T extends IIdentity> T getParentIdentity(Class<T> type);

	/*
	 * Provided to simplify implementing the getParentIdentity method.
	 */
	/*
	 * <p> findParent. </p>
	 *
	 * @param child a {@link org.integratedmodelling.klab.api.auth.IIdentity}
	 * object.
	 * 
	 * @param type a {@link java.lang.Class} object.
	 * 
	 * @param <T> a T object.
	 * 
	 * @return a T object.
	 */
	@SuppressWarnings("unchecked")
	static <T extends IIdentity> T findParent(IIdentity child, Class<T> type) {
		return child == null ? null
				: (type.isAssignableFrom(child.getClass()) ? (T) child : findParent(child.getParentIdentity(), type));
	}
}
