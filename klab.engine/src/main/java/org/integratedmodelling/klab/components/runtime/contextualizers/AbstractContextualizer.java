package org.integratedmodelling.klab.components.runtime.contextualizers;

import org.integratedmodelling.kim.api.IContextualizable;
import org.integratedmodelling.kim.api.IPrototype;
import org.integratedmodelling.kim.api.IPrototype.Argument;
import org.integratedmodelling.klab.api.model.contextualization.IContextualizer;
import org.integratedmodelling.klab.api.observations.IObservation;
import org.integratedmodelling.klab.api.observations.IState;
import org.integratedmodelling.klab.api.provenance.IArtifact;
import org.integratedmodelling.klab.api.runtime.IContextualizationScope;
import org.integratedmodelling.klab.common.mediation.Unit;
import org.integratedmodelling.klab.components.runtime.RuntimeScope;
import org.integratedmodelling.klab.dataflow.DataflowHandler;
import org.integratedmodelling.klab.exceptions.KlabIllegalArgumentException;
import org.integratedmodelling.klab.exceptions.KlabIllegalStateException;
import org.integratedmodelling.klab.exceptions.KlabResourceNotFoundException;

/**
 * Helper class to facilitate access to the contextualizer declaration and units management in
 * states.
 * 
 * @author Ferd
 *
 */
public abstract class AbstractContextualizer implements IContextualizer {

    private IPrototype prototype;
    private RuntimeScope scope;

    protected IPrototype getPrototype() {
        return prototype;
    }

    public void setPrototype(IPrototype prototype) {
        this.prototype = prototype;
    }

    protected RuntimeScope getScope() {
        return scope;
    }

    public void setScope(RuntimeScope scope) {
        this.scope = scope;
    }

    /**
     * Return the observation identified in the declaration as an import, verifying the match
     * between the declaration and the scope. If units were specified, wrap it in a mediator if
     * necessary, performing any needed recontexualization.
     * 
     * @param stateIdentifier
     * @return a state or wrapping mediator
     * @throws KlabIllegalArgumentException if the identifier was not declared
     * @throws KlabIllegalStateException if the unit or the data type for the state are not
     *         compatible with the declaration and the contextualization scope
     * @throws KlabResourceNotFoundException if the state is missing and the dependency isn't
     *         optional
     */
    @SuppressWarnings("unchecked")
    public <T extends IObservation> T getInput(String stateIdentifier, Class<T> cls) {

        Argument input = null;
        for (Argument imp : prototype.listImports()) {
            if (stateIdentifier.equals(imp.getName())) {
                input = imp;
                break;
            }
        }
        if (input == null) {
            throw new KlabIllegalArgumentException("illegal request for undeclared input '" + stateIdentifier
                    + "' in function " + prototype.getName());
        }

        T artifact = null;

        if (input.getUnit() != null && IState.class.isAssignableFrom(cls)) {
            artifact = (T) scope.getState(stateIdentifier, Unit.create(input.getUnit()));
        } else if (input.getUnit() == null) {
            artifact = scope.getArtifact(stateIdentifier, cls);
            if (artifact != null && artifact.getObservable().getArtifactType() != input.getType()) {
                throw new KlabIllegalStateException("input '" + stateIdentifier + "' in function "
                        + prototype.getName() + " is not of the declared " + input.getType()
                        + " type (actual = " + artifact.getObservable().getArtifactType() + ")");
            }
        } else {
            throw new KlabIllegalStateException("illegal request for units in non-state input '"
                    + stateIdentifier + "' in function " + prototype.getName());
        }

        if (!input.isOptional() && artifact == null) {
            throw new KlabResourceNotFoundException("mandatory input " + stateIdentifier
                    + " is missing in contextualizer " + prototype.getName());
        }

        return artifact;
    }

    @SuppressWarnings("unchecked")
    public <T extends IObservation> T getOutput(String stateIdentifier, Class<T> cls) {

        Argument input = null;
        for (Argument imp : prototype.listExports()) {
            if (stateIdentifier.equals(imp.getName())) {
                input = imp;
                break;
            }
        }
        if (input == null) {
            throw new KlabIllegalArgumentException("illegal request for undeclared input '" + stateIdentifier
                    + "' in function " + prototype.getName());
        }

        T artifact = null;

        if (input.getUnit() != null && IState.class.isAssignableFrom(cls)) {
            artifact = (T) scope.getState(stateIdentifier, Unit.create(input.getUnit()));
        } else if (input.getUnit() == null) {
            artifact = scope.getArtifact(stateIdentifier, cls);
            if (artifact.getObservable().getArtifactType() != input.getType()) {
                throw new KlabIllegalStateException("input '" + stateIdentifier + "' in function "
                        + prototype.getName() + " is not of the declared " + input.getType()
                        + " type (actual = " + artifact.getObservable().getArtifactType() + ")");
            }
        } else {
            throw new KlabIllegalStateException("illegal request for units in non-state input '"
                    + stateIdentifier + "' in function " + prototype.getName());
        }

        if (!input.isOptional() && artifact == null) {
            throw new KlabResourceNotFoundException("mandatory output " + stateIdentifier
                    + " is missing in contextualizer " + prototype.getName());
        }

        return artifact;
    }

	@Override
	public void notifyContextualizedResource(IContextualizable resource, IArtifact target,
			IContextualizationScope scope) {
	}
    
    

}
