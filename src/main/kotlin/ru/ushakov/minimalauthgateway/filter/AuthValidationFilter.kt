package ru.ushakov.minimalauthgateway.filter

import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import ru.ushakov.minimalauthgateway.util.UrlConstants.AUTH_SERVICE_URL

@Component
class AuthValidationFilter(
    private val webClient: WebClient.Builder
) : AbstractGatewayFilterFactory<Any>() {

    override fun apply(config: Any?): GatewayFilter {
        return GatewayFilter { exchange, chain ->
            val token = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)?.substringAfter("Bearer ")
            if (token.isNullOrEmpty()) {
                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                return@GatewayFilter exchange.response.setComplete()
            }

            webClient.build()
                .get()
                .uri("$AUTH_SERVICE_URL/api/v1/auth/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer $token")
                .retrieve()
                .onStatus({ status -> status.is4xxClientError || status.is5xxServerError }) {
                    Mono.error(RuntimeException("Invalid access token"))
                }
                .bodyToMono(Void::class.java)
                .flatMap { chain.filter(exchange) }
                .onErrorResume {
                    handleTokenRefresh(exchange, chain)
                }
        }
    }

    private fun handleTokenRefresh(exchange: ServerWebExchange, chain: GatewayFilterChain): Mono<Void> {
        val refreshToken = exchange.request.headers.getFirst("RefreshToken")
        return if (refreshToken.isNullOrEmpty()) {
            exchange.response.statusCode = HttpStatus.UNAUTHORIZED
            exchange.response.setComplete()
        } else {
            webClient.build()
                .post()
                .uri("$AUTH_SERVICE_URL/api/v1/auth/token/refresh")
                .bodyValue(mapOf("refreshToken" to refreshToken))
                .retrieve()
                .onStatus({ status -> status.is4xxClientError || status.is5xxServerError }) {
                    Mono.error(RuntimeException("Invalid refresh token"))
                }
                .bodyToMono(Map::class.java)
                .flatMap { tokenResponse ->
                    // Set new access token in request headers
                    val newAccessToken = tokenResponse["token"].toString()
                    val newExchange = exchange.mutate().request(
                        exchange.request.mutate().header(HttpHeaders.AUTHORIZATION, "Bearer $newAccessToken").build()
                    ).build()
                    chain.filter(newExchange)
                }
        }
    }
}