package org.integratedmodelling.klab.node;

import java.util.Arrays;

import javax.annotation.PreDestroy;
import javax.inject.Singleton;

import org.apache.catalina.startup.Tomcat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.env.Environment;
import org.springframework.http.converter.protobuf.ProtobufHttpMessageConverter;
import org.springframework.http.converter.protobuf.ProtobufJsonFormatHttpMessageConverter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@Singleton
@EnableAutoConfiguration
@ComponentScan(basePackages = { "org.integratedmodelling.klab.node.security",
		"org.integratedmodelling.klab.node.resources", "org.integratedmodelling.klab.node.controllers",
		"org.integratedmodelling.klab.node.services" })
public class NodeApplication {
	
	// property specifying the resource online checking interval in seconds
	public static final String RESOURCE_CHECKING_INTERVAL_SECONDS = "klab.node.resources.checkinterval";
	
	private static Node node;
	
	public void run(String[] args) {
		NodeStartupOptions options = new NodeStartupOptions();
		options.initialize(args);
		node = Node.start(options);
	}

	@PreDestroy
	public void shutdown() {
		// TODO engine shutdown if needed
	}

	@Bean
	public ProtobufJsonFormatHttpMessageConverter ProtobufJsonFormatHttpMessageConverter() {
		return new ProtobufJsonFormatHttpMessageConverter();
	}

	@Bean
	public RestTemplate restTemplate(ProtobufHttpMessageConverter hmc) {
		return new RestTemplate(Arrays.asList(hmc));
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public ServletWebServerFactory servletContainer() {
		TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory() {
			@Override
			protected TomcatWebServer getTomcatWebServer(Tomcat tomcat) {
//				try {
//					Context context = tomcat.addWebapp("/kgit", Node.gitWarPath.getAbsolutePath());
//					WebappLoader loader = new WebappLoader(Thread.currentThread().getContextClassLoader());
//					context.setLoader(loader);
//				} catch (ServletException e) {
//					throw new IllegalStateException("could not deploy the Git server from the embedded war");
//				}
				return super.getTomcatWebServer(tomcat);
			}
		};
		return tomcat;
	}

	public static void main(String args[]) {
		new NodeApplication().run(args);
	}

}
