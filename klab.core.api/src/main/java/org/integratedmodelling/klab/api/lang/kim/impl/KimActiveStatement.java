package org.integratedmodelling.klab.api.lang.kim.impl;

import org.integratedmodelling.klab.api.lang.kim.KKimActiveStatement;
import org.integratedmodelling.klab.api.lang.kim.KKimBehavior;

/**
 * An active statement encodes an object that can have a runtime behavior specified through
 * contextualization actions.
 * 
 * @author ferdinando.villa
 *
 */
public class KimActiveStatement extends KimStatement implements KKimActiveStatement {

    private static final long serialVersionUID = -8237389232551882921L;
    
    private KKimBehavior behavior;

    @Override
    public KKimBehavior getBehavior() {
        return behavior;
    }

    public void setBehavior(KKimBehavior behavior) {
        this.behavior = behavior;
    }

}
