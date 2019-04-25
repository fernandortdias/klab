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
package org.integratedmodelling.klab.api.runtime.dataflow;

import org.integratedmodelling.klab.api.observations.IObservation;
import org.integratedmodelling.klab.api.observations.scale.IScale;
import org.integratedmodelling.klab.api.provenance.IArtifact;
import org.integratedmodelling.klab.api.resolution.ICoverage;
import org.integratedmodelling.klab.api.runtime.IRuntimeProvider;
import org.integratedmodelling.klab.api.runtime.monitoring.IMonitor;
import org.integratedmodelling.klab.exceptions.KlabException;

/**
 * Dataflows in k.LAB represent "raw" computations, which create, compute and link
 * {@link org.integratedmodelling.klab.api.data.artifacts.IObjectArtifact}s in response to a request
 * for observation of a given semantic
 * {@link org.integratedmodelling.klab.api.resolution.IResolvable}. The computation is stripped of
 * all semantics; therefore it can be run by a semantically-unaware workflow system.
 * <p>
 * Dataflows are serialized and rebuilt from KDL specifications by
 * {@link org.integratedmodelling.klab.api.services.IDataflowService}. Dataflows are also built by
 * the engine after resolving a IResolvable, and can be serialized to KDL if necessary using
 * {@link #getKdlCode()}.
 * <p>
 * The end result of {@link #run(IScale, IMonitor) running a dataflow} in a given scale is a
 * {@link org.integratedmodelling.klab.api.provenance.IArtifact}. In k.LAB, this corresponds to
 * either a {@link org.integratedmodelling.klab.api.observations.IObservation} (the usual case) or a
 * {@link org.integratedmodelling.klab.api.model.IModel} (when the computation is a learning
 * activity, which builds an explanation of a process). Dataflows built
 * {@link org.integratedmodelling.klab.api.services.IObservationService#resolve(String, org.integratedmodelling.klab.api.runtime.ISession, String[])
 * within the k.LAB runtime} as a result of a semantic resolution will produce {@link IObservation
 * observations}, i.e. semantic artifacts. But if those dataflows are {@link #getKdlCode()
 * serialized}, loaded and run, they will produce non-semantic artifacts as the semantic information
 * is not preserved in the dataflow specifications.
 * <p>
 * Dataflows written by users or created by k.LAB can be stored on k.LAB nodes as URN-specified
 * computations, which can be referenced in k.LAB models. The KDL language that specified dataflows
 * is also used to define service contracts for k.IM-callable services or remote computations
 * accessed through REST calls.
 * <p>
 * A dataflow is the top-level {@link IActuator actuator} of a k.LAB computation. It adds top-level
 * semantics to the actuator's contract. Only a dataflow can be run and serialized from the API.
 * <p>
 * The KDL specification and the parser provided in the klab-kdl project provide a bridge to
 * different workflow systems. Models of computation are inferred in k.LAB and depend on the
 * specific {@link IRuntimeProvider runtime} adopted as well as on the semantics of the services
 * (actors) used; exposing the computational model is work in progress.
 * <p>
 * TODO expose all metadata and context fields.
 * <p>
 *
 * @author ferdinando.villa
 * @version $Id: $Id
 * @param <T> the most specific type of artifact this dataflow will build when run.
 * @since 0.10.0
 */
public interface IDataflow<T extends IArtifact> extends IActuator {

  /**
   * The dataflow is the result of resolving a URN. If {@link org.integratedmodelling.klab.api.resolution.ICoverage#isEmpty() its coverage is
   * empty}, the dataflow will produce an {@link org.integratedmodelling.klab.api.provenance.IArtifact#isEmpty() empty artifact} when run.
   * Otherwise the coverage reflects the applicable scale of the dataflow, i.e. the range of extents
   * and resolutions where it applies.
   *
   * @return the coverage of this dataflow.
   */
	ICoverage getCoverage();

  /**
   * Run the dataflow in the passed scale using the configured or default {@link org.integratedmodelling.klab.api.runtime.IRuntimeProvider}
   * and return the resulting artifact.
   *
   * @param scale the scale of contextualization. Assumed (and not checked) compatible with the
   *        scale of the resolution that generated this dataflow.
   *
   *        TODO the scale should be checked against the coverage and the empty artifact should be
   *        returned if incompatible.
   * @param monitor a {@link org.integratedmodelling.klab.api.runtime.monitoring.IMonitor} object.
   * @return the built artifact. May be empty, never null.
   * @throws org.integratedmodelling.klab.exceptions.KlabException
   */
  T run(IScale scale, IMonitor monitor) throws KlabException;

  /**
   * Return the KDL source code for the dataflow. If the dataflow has been read from a KLD stream,
   * return the original code, otherwise reconstruct it by decompiling the dataflow.
   *
   * @return the KDL code. Never null.
   */
  String getKdlCode();

  /**
   * An empty dataflow results from an unsuccessful resolution and produces an
   * {@link org.integratedmodelling.klab.api.provenance.IArtifact#isEmpty() empty artifact} when run.
   *
   * @return true if the dataflow is empty
   */
  boolean isEmpty();

}
