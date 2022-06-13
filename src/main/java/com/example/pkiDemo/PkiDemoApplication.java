package com.example.pkiDemo;

import org.apache.catalina.connector.Connector;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class PkiDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(PkiDemoApplication.class, args);
	}
	
	
	@Bean //포트 8080에서 HTTP 요청을 수신하는 컨테이너를 생성
	public ServletWebServerFactory serverFactory() { 
		TomcatServletWebServerFactory tomcatServletWebServerFactory = new TomcatServletWebServerFactory();
		tomcatServletWebServerFactory.addAdditionalTomcatConnectors(createStandardConnector());

		return tomcatServletWebServerFactory;
	}
	
	//tomcat response
	private Connector createStandardConnector() {
		Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
		connector.setPort(8080);
		//connector.setPort(8443);
		
		return connector;
	}
}
 
