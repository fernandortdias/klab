package org.integratedmodelling.klab.engine;

import java.util.Arrays;
import java.util.stream.StreamSupport;

import javax.annotation.PreDestroy;
import org.integratedmodelling.klab.Configuration;
import org.integratedmodelling.klab.api.auth.ICertificate;
import org.integratedmodelling.klab.auth.KlabCertificate;
import org.integratedmodelling.klab.exceptions.KlabException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.http.converter.protobuf.ProtobufHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;


@ComponentScan(basePackages = { "org.integratedmodelling.klab.engine"})
@Component
@ConditionalOnProperty(
        value="spring.cloud.consul.enabled", 
        havingValue = "true", 
        matchIfMissing = false)
public class EngineRunner implements ApplicationListener<ApplicationPreparedEvent>{


	@Bean
	public ProtobufHttpMessageConverter protobufHttpMessageConverter() {
		return new ProtobufHttpMessageConverter();
	}

	
	@Bean
	public RestTemplate restTemplate(ProtobufHttpMessageConverter hmc) {
		return new RestTemplate(Arrays.asList(hmc));
	}
	
	@Bean
	public RemoteEngineService remoteEngineService() {
		RemoteEngineService service = new RemoteEngineService();
		service.setEngine(engine);
		return service;
	}

	public EngineRunner() {
	}
	
	
	private static RemoteEngine engine;
	private static Environment environment;
	private ICertificate certificate;
	
	public static EngineRunner start(ApplicationPreparedEvent event) {
		environment = event.getApplicationContext().getEnvironment();
		return run();
		
	}

	
	private static EngineRunner run() {
		EngineRunner ret = new EngineRunner();
		if(!ret.boot()){
			throw new KlabException("Engine failed to start");
		};
		
		return ret;	
	}


	@PreDestroy
	public void shutdown() {
		engine.stop();
	}
	
	
	private boolean boot() {
		try {
		    String consul = environment.getProperty("spring.cloud.consul.enabled");
		    if(consul == "true") {
		        String certString = environment.getProperty("klab.certificate");
		        this.certificate = KlabCertificate.createFromString(certString);
		        setPropertiesFromEnvironment(environment);
		        engine = RemoteEngine.start(this.certificate, new EngineStartupOptions());
		    } else {
		        engine = RemoteEngine.start(null, new EngineStartupOptions());
		    }
			
		} catch (Throwable e) {
			return false;
		}
		return true;
	}

	
	private static void setPropertiesFromEnvironment(Environment environment) {
		MutablePropertySources propSrcs =  ((ConfigurableEnvironment) environment).getPropertySources();
		StreamSupport.stream(propSrcs.spliterator(), false)
		        .filter(ps -> ps instanceof EnumerablePropertySource)
		        .map(ps -> ((EnumerablePropertySource) ps).getPropertyNames())
		        .flatMap(Arrays::<String>stream)
		        .forEach(propName -> Configuration.INSTANCE.getProperties().setProperty(propName, environment.getProperty(propName)));
		Configuration.INSTANCE.save();
		return;
	}

	
	@Override
	public void onApplicationEvent(ApplicationPreparedEvent event) {
		if (engine == null) {
			start(event);
		} else {
			return;
		}
	}

}
