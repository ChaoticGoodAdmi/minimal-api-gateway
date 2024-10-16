package ru.ushakov.minimalauthgateway.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .csrf { csrf -> csrf.disable() }
            .authorizeExchange { exchanges ->
                exchanges
                    .pathMatchers(
                        "/api/v1/auth/**",
                        "/api/v1/user/**"
                    ).permitAll()
                    .anyExchange().authenticated()
            }
            .build()
    }
}