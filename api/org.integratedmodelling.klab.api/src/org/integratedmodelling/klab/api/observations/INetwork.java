package org.integratedmodelling.klab.api.observations;

import java.io.OutputStream;
import java.util.Collection;

import org.integratedmodelling.klab.utils.Triple;

/**
 * A network is, for the time being, a possible view of a configuration. If they are networks 
 * configurations will return a network using the as() method. 
 * 
 * @author Ferd
 *
 */
public interface INetwork {

    /**
     * Return a list of triples ID/Description/FileExtension for all the formats of file export that
     * this adapter supports for the passed observation. Same as the equally named method in the
     * adapter API.
     * 
     * @param observation
     * @return
     */
    Collection<Triple<String, String, String>> getExportCapabilities(IObservation observation);

    /**
     * Export the network on the passed output stream using the passed format. Formats
     * are implementation-dependent.
     * 
     * @param outputFormat
     * @param outputStream
     */
    void export(String outputFormat, OutputStream outputStream);

}
