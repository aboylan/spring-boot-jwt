package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader("Authorization");

		if (!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}
		boolean validoToken;
		Claims token = null;
		try {
			token = Jwts.parserBuilder().setSigningKey(Keys.secretKeyFor(SignatureAlgorithm.HS512)).build()
					.parseClaimsJws(header.replace("Bearer ", "")).getBody();
			validoToken = true;
		} catch (JwtException | IllegalArgumentException e) {
			validoToken = false;
		}
		
	}

	private boolean requiresAuthentication(String header) {
		if (header == null || !header.startsWith("Bearer ")) {
			return false;
		}
		return true;
	}

}
