package ru.proba.gateway.config;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint.DelegateEntry;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final String LOGIN_URL = "/oauth2/authorization/keycloak";

    @Bean
    SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveClientRegistrationRepository clientRegistrations,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
            @Value("${gateway.security.csrf.enabled:true}") boolean csrfEnabled) {

        http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/actuator/health/**", "/oauth2/**", "/login/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestResolver(pkceAuthorizationRequestResolver(clientRegistrations))
                        .authorizedClientRepository(authorizedClientRepository))
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint()))
                .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrations)));

        if (csrfEnabled) {
            http
                    .csrf(csrf -> csrf
                            .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                            .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()))
                    .addFilterAfter(new CsrfCookieWebFilter(), SecurityWebFiltersOrder.CSRF);
        } else {
            http.csrf(ServerHttpSecurity.CsrfSpec::disable);
        }

        return http.build();
    }

    @Bean
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    @Bean
    ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrations,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

        ReactiveOAuth2AuthorizedClientProvider provider = ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();

        DefaultReactiveOAuth2AuthorizedClientManager manager =
                new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrations, authorizedClientRepository);
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    private ServerOAuth2AuthorizationRequestResolver pkceAuthorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrations) {

        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrations);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    private ServerAuthenticationEntryPoint authenticationEntryPoint() {
        DelegatingServerAuthenticationEntryPoint entryPoint = new DelegatingServerAuthenticationEntryPoint(
                new DelegateEntry(
                        ServerWebExchangeMatchers.pathMatchers("/api/**"),
                        new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)));
        entryPoint.setDefaultEntryPoint(new RedirectServerAuthenticationEntryPoint(LOGIN_URL));
        return entryPoint;
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(
            ReactiveClientRegistrationRepository clientRegistrations) {

        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrations);
        handler.setPostLogoutRedirectUri("{baseUrl}");
        return handler;
    }

    private static class CsrfCookieWebFilter implements WebFilter {

        @Override
        public Mono<Void> filter(ServerWebExchange exchange, @NonNull WebFilterChain chain) {
            Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
            return csrfToken != null ? csrfToken.then(chain.filter(exchange)) : chain.filter(exchange);
        }
    }
}
