package com.bolsadeideas.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.bolsadeideas.springboot.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SpringSecurityConfig {

	//@Autowired
	//private LoginSuccessHandler successHandler;

	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@Autowired
    private JpaUserDetailsService userDetailService;

	@Autowired
	private AuthenticationConfiguration authenticationConfiguration;

	@Autowired
	private JWTService jwtService;
	
	@Bean
	AuthenticationManager authenticationManager() throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Autowired
	public void userDetailsService(AuthenticationManagerBuilder build) throws Exception {
		build.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
	}

	@Bean
	MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
		return new MvcRequestMatcher.Builder(introspector);
	}

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {

		http.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers(mvc.pattern("/"), mvc.pattern("/css/**"), mvc.pattern("/js/**"),
						mvc.pattern("/images/**"), mvc.pattern("/listar**"), mvc.pattern("/locale"))
				.permitAll()
				.anyRequest().authenticated());

		//http.formLogin(form -> form.successHandler(successHandler).loginPage("/login").permitAll());
		//http.logout(logout -> logout.permitAll());
		//http.exceptionHandling(sec -> sec.accessDeniedPage("/error_403"));
		http.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService));
		http.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService));
		http.csrf(csrf -> csrf.disable());
		http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}

}
