package org.integratedmodelling.klab.api.knowledge.observation;

import org.integratedmodelling.klab.api.data.KMetadata;
import org.integratedmodelling.klab.api.knowledge.observation.scale.KScale;

/**
 * A configuration of any kind, observable as a construct of a human observer's
 * mind. Certain observations may exist because of a generating pattern:
 * configurations (which are the reification of an observed pattern and can only
 * "emerge" from the observation of other observables) as well as subjects and
 * processes, which can emerge from the observation of structural and functional
 * relationships (respectively).
 * <p>
 * Patterns that incarnate into direct observations should be able to provide
 * their own scale.
 * <p>
 * A specialized pattern resulting from interactions between observations is the
 * {@link INetwork}.
 * 
 * @author Ferd
 *
 */
public interface KPattern extends Iterable<KObservation> {

	/**
	 * Called when a new observation that triggers this pattern appears after the
	 * pattern has been created.
	 */
	void update(KObservation trigger);

	/**
	 * If the pattern embodies scale, this should be computed when this is called.
	 * If no specific scale can be computed, the one passed should be returned.
	 * 
	 * @param embodyingScale the scale of the contextualization scope
	 * @return
	 */
	KScale getScale(KScale embodyingScale);

	/**
	 * Return any metadata associated with the pattern. At the moment there is no
	 * established mechanism to specify the metadata, so those associated with the
	 * concept should be used.
	 * 
	 * @return
	 */
	KMetadata getMetadata();

	/**
	 * The pattern should be able to provide a name for itself. If it incarnates a
	 * countable, this name should be differentiated within a series of related
	 * patterns.
	 * 
	 * @return
	 */
	String getName();

}
