package org.integratedmodelling.klab.hub.security;

import java.io.IOException;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.integratedmodelling.klab.Logging;
import org.integratedmodelling.klab.hub.api.TokenAuthentication;
import org.integratedmodelling.klab.hub.repository.TokenRepository;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

@Order(Ordered.HIGHEST_PRECEDENCE)
public class KeycloakFilter extends OncePerRequestFilter { 
    
    @Autowired
    private TokenRepository tokenRepository;

//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//      //1. Authentication Decision
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        String opid = httpRequest.getHeader("opid");
//        
//        if (opid == null || !Boolean.parseBoolean(opid)) {
//            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
//            Authentication authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
//            newContext.setAuthentication(authentication);
//            SecurityContextHolder.setContext(newContext);
//        } else {
//            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//            newContext.setAuthentication(authentication);
//            SecurityContextHolder.setContext(newContext);
//        }
//        
//        chain.doFilter(request, response);
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // //1. Authentication Decision
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String opid = httpRequest.getHeader("opid");
        
        if (opid != null && Boolean.parseBoolean(opid)) {
            new KeycloakSecurityContext().getAuthorizationContext();
//            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
//            KeycloakSecurityContext keycloakSecurityContext = new KeycloakSecurityContext();
//            Authentication authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
//            keycloakSecurityContext.getAuthorizationContext().
//            newContext.setAuthentication(authentication);
//            SecurityContextHolder.setContext(newContext);
//            return new KeycloakFilter( KeycloakTokenValidator.builder()
//                    .build(jwkUrl, resource, jwtClaim));
            filterChain.doFilter(request, response);
        } else {
//            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//            newContext.setAuthentication(authentication);
//            SecurityContextHolder.setContext(newContext);
            try {
                
                String tokenString = ((HttpServletRequest) request)
                        .getHeader(WebSecurityConfig.AUTHENTICATION_TOKEN_HEADER_NAME);
                if (tokenString != null) {
                    Optional<TokenAuthentication> token = tokenRepository.findByTokenString(tokenString);
                    if(token.isPresent()) {
                        TokenAuthentication storedToken = token.get();
                        if (storedToken.isAuthenticated()) {
                            PreAuthenticatedAuthenticationToken authToken = new PreAuthenticatedAuthenticationToken(storedToken.getPrincipal()
                                    ,storedToken.getCredentials(),storedToken.getAuthorities());
                            // successful match. token should contain everything the security context needs.
                            SecurityContextHolder.getContext().setAuthentication(authToken);
                        }
                    }
                }
            } catch (Throwable e) {
              Logging.INSTANCE.error("Could not set user authentication in security context " + e.toString());
            } finally {
                SecurityContextHolder.getContext();
                filterChain.doFilter(request, response);
            }
        }
        
        
        
    }
    

}
