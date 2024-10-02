package x.erp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ErpGatewayServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ErpGatewayServiceApplication.class, args);
	}


	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
		return builder.routes()
				.route("service1_route", r -> r.path("/api/**","/erp/**", "/page/**")
						.uri("http://localhost:8080"))
				.route("service2_route", r -> r.path("/service2/**")
						.filters(f -> f.stripPrefix(1))
						.uri("http://localhost:8082"))
				.build();
	}

}
