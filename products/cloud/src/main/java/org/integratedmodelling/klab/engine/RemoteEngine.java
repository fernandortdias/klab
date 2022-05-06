package org.integratedmodelling.klab.engine;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import org.integratedmodelling.klab.Authentication;
import org.integratedmodelling.klab.Configuration;
import org.integratedmodelling.klab.Logging;
import org.integratedmodelling.klab.Logo;
import org.integratedmodelling.klab.Version;
import org.integratedmodelling.klab.api.auth.ICertificate;
import org.integratedmodelling.klab.api.engine.IEngineStartupOptions;
import org.integratedmodelling.klab.auth.AnonymousEngineCertificate;
import org.integratedmodelling.klab.auth.KlabCertificate;
import org.integratedmodelling.klab.engine.events.UserEventPublisher;
import org.integratedmodelling.klab.engine.runtime.Session;
import org.integratedmodelling.klab.engine.services.AgentServiceCheck;
import org.integratedmodelling.klab.engine.services.ConsulDnsService;
import org.integratedmodelling.klab.exceptions.KlabAuthorizationException;
import org.integratedmodelling.klab.exceptions.KlabException;

public class RemoteEngine extends Engine {

    private static final long serialVersionUID = -7180871922872370852L;

    private Long sessionDeadBand = 8L;
    private ConsulDnsService dnsService;
    private UserEventPublisher publisher;
    private AgentServiceCheck check;

    public RemoteEngine( ICertificate certificate ) {
        super(certificate);
    }

    public static RemoteEngine start(ICertificate certificate, IEngineStartupOptions options) {

        if (certificate == null) {

            if (options.isAnonymous()) {
                certificate = new AnonymousEngineCertificate();
            } else {

                if (options.getCertificateResource() != null) {
                    certificate = KlabCertificate.createFromClasspath(options.getCertificateResource());
                } else {
                    File certFile = options.getCertificateFile();
                    if (!certFile.exists()) {
                        // check for legacy certificate
                        certFile = new File(Configuration.INSTANCE.getDataPath() + File.separator + "im.cert");
                    }
                    certificate = certFile.exists() ? KlabCertificate.createFromFile(certFile) : KlabCertificate.createDefault();
                }
            }
        }

        if (!certificate.isValid()) {
            throw new KlabAuthorizationException("certificate is invalid: " + certificate.getInvalidityCause());
        }

        RemoteEngine ret = new RemoteEngine(certificate);

        if (!ret.boot(options)) {
            throw new KlabException("engine failed to start");
        }

        if (certificate.getType() == ICertificate.Type.ENGINE) {
            System.out.println("\n" + Logo.ENGINE_BANNER);
            System.out.println("\nStartup successful: " + ret.getUsername() + " v" + Version.CURRENT + " on " + new Date());
        }
        return ret;
    }

    @Override
    protected void closeExpiredSessions() {
        if (!Authentication.INSTANCE.getSessions().isEmpty()) {
            try {
                long current = System.currentTimeMillis();
                activeSessions().forEach(sesh -> {
                    long last = sesh.getLastActivity() + (sessionDeadBand * 60000);
                    if (last < (current)) {
                        try {
                            Logging.INSTANCE.info("Killing session " + sesh.getId());
                            sesh.close();
                            publisher.logout(null, sesh, true);
                        } catch (IOException e) {
                            // I do not want to throw anything because the thread would die
                            Logging.INSTANCE.info("Error closing inactive session or removing dead weight.");
                        }
                    }
                });
            } catch (Exception e) {
                Logging.INSTANCE.info(e.toString());
            }
        }
    }

    private Set<Session> activeSessions() {
        Set<Session> sessions = new HashSet<>();
        Authentication.INSTANCE.getSessions().forEach(s -> {
            Session sesh = Authentication.INSTANCE.getIdentity(s.getId(), Session.class);
            sessions.add(sesh);
        });
        return sessions;
    }

    public void setDnsService(ConsulDnsService dnsService) {
        this.dnsService = dnsService;
    }

    public AgentServiceCheck getCheck() {
        return check;
    }

    public void setCheck(AgentServiceCheck check) {
        this.check = check;
        check.start();
    }

    public void setPublisher(UserEventPublisher publisher) {
        this.publisher = publisher;
    }
    
    public void setSessionDeadBand(Long value) {
        this.sessionDeadBand = value;
    }
}
