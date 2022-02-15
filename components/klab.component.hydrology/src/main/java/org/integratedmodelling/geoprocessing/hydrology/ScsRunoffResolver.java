package org.integratedmodelling.geoprocessing.hydrology;

import static org.hortonmachine.gears.libs.modules.HMConstants.floatNovalue;

import java.awt.image.DataBuffer;

import org.geotools.coverage.grid.GridCoverage2D;
import org.hortonmachine.hmachine.modules.hydrogeomorphology.scsrunoff.OmsScsRunoff;
import org.integratedmodelling.geoprocessing.TaskMonitor;
import org.integratedmodelling.kim.api.IParameters;
import org.integratedmodelling.klab.api.data.general.IExpression;
import org.integratedmodelling.klab.api.model.contextualization.IResolver;
import org.integratedmodelling.klab.api.observations.IProcess;
import org.integratedmodelling.klab.api.observations.IState;
import org.integratedmodelling.klab.api.provenance.IArtifact.Type;
import org.integratedmodelling.klab.api.runtime.IContextualizationScope;
import org.integratedmodelling.klab.components.geospace.utils.GeotoolsUtils;
import org.integratedmodelling.klab.components.runtime.contextualizers.AbstractContextualizer;
import org.integratedmodelling.klab.exceptions.KlabException;

public class ScsRunoffResolver extends AbstractContextualizer implements IResolver<IProcess>, IExpression {

    @Override
    public Type getType() {
        return Type.PROCESS;
    }

    @Override
    public IProcess resolve(IProcess runoffProcess, IContextualizationScope context) throws KlabException {
        
        TaskMonitor taskMonitor = new TaskMonitor(context.getMonitor());
        taskMonitor.setTaskName("SCS Runoff");

        IState rainfallVolumeState = getInput("rainfall_volume", IState.class);
        IState streamPresenceState = getInput("presence_of_stream", IState.class);
        IState curveNumberState = getInput("curve_number", IState.class);

//        if (rainfallVolumeState != null && streamPresenceState != null && curveNumberState != null) {
            
            IState numberOfEventsState = getInput("number_of_storm_events", IState.class);
            if (numberOfEventsState == null) {
                context.getMonitor().warn("No number of events available, default to 1.");
            }

            IState runoffState = getOutput("runoff_water_volume", IState.class);

            OmsScsRunoff scsRunoff = new OmsScsRunoff();
            scsRunoff.pm = taskMonitor;
            scsRunoff.inRainfall = getGridCoverage(context, rainfallVolumeState);
            scsRunoff.inNet = getGridCoverage(context, streamPresenceState);
            scsRunoff.inCurveNumber = getGridCoverage(context, curveNumberState);
            scsRunoff.inNumberOfEvents = getGridCoverage(context, numberOfEventsState);
            try {
                scsRunoff.process();
            } catch (Exception e) {
                throw new KlabException(e);
            }
            if (!context.getMonitor().isInterrupted()) {
                GeotoolsUtils.INSTANCE.coverageToState(scsRunoff.outputDischarge, runoffState, context.getScale(), null);
            }

            GeotoolsUtils.INSTANCE.dumpToRaster(context, "ScsRunoff", rainfallVolumeState, streamPresenceState, curveNumberState,
                    runoffState, numberOfEventsState);
//        }
        return runoffProcess;
    }

    private GridCoverage2D getGridCoverage(IContextualizationScope context, IState state) {
        if (state == null) {
            return null;
        }
        return GeotoolsUtils.INSTANCE.stateToCoverage(state, context.getScale(), DataBuffer.TYPE_FLOAT, floatNovalue, false);
    }

    @Override
    public Object eval(IParameters<String> parameters, IContextualizationScope context) throws KlabException {
        return new ScsRunoffResolver();
    }

}
