package org.integratedmodelling.klab.api.services;

import org.integratedmodelling.klab.api.identities.KUserIdentity;
import org.integratedmodelling.klab.api.knowledge.observation.scope.KScope;

public interface KEngine {


    /**
     * Login through an authenticated user identity and return the root scope for that user. The
     * scope for the user should be stored: if the user was logged in previously, the previously
     * logged in scope should be returned..
     * 
     * @param user
     * @return
     */
    KScope login(KUserIdentity user);
}
