package ru.ushakov.minimalauthgateway.filter

import com.nimbusds.common.contenttype.ContentType
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import ru.ushakov.minimalauthgateway.util.UrlConstants

@Component
class UserRequestFilter(
    private val webClient: WebClient.Builder
) : AbstractGatewayFilterFactory<Any>() {

    override fun apply(config: Any?): GatewayFilter =
        GatewayFilter { exchange: ServerWebExchange, chain ->
            val accessToken = extractBearerToken(exchange)
            val refreshToken = exchange.request.headers.getFirst("RefreshToken")

            if (accessToken == null) {
                exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                return@GatewayFilter exchange.response.setComplete()
            }

            webClient.build().get()
                .uri("${UrlConstants.AUTH_SERVICE_URL}/api/v1/token/validate")
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
                .retrieve()
                .onStatus({ status -> status == HttpStatus.UNAUTHORIZED }) {
                    when (refreshToken) {
                        null -> Mono.error(Throwable("Access token is expired, refresh token is invalid"))
                        else -> {
                            refreshAuthToken(exchange, chain, refreshToken)
                                .flatMap { Mono.empty<Throwable>() }
                                .onErrorResume { error ->
                                    Mono.error(Throwable("Error during token refresh: ${error.message}"))
                                }
                        }
                    }
                }
                .onStatus({ status -> status.isError }) { response ->
                    response.bodyToMono(String::class.java).flatMap { errorMessage ->
                        exchange.response.statusCode = response.statusCode()
                        exchange.response.headers[HttpHeaders.CONTENT_TYPE] =
                            listOf(ContentType.APPLICATION_JSON.toString())
                        exchange.response.writeWith(
                            Mono.just(
                                exchange.response.bufferFactory().wrap(errorMessage.toByteArray())
                            )
                        )
                            .then(Mono.error(Throwable("Error: $errorMessage")))
                    }
                }
                .bodyToMono(String::class.java)
                .flatMap {
                    val claims = decodeJwt(accessToken)
                    val tokenUserId = claims["userId"] as Int?

                    if (tokenUserId == null) {
                        exchange.response.statusCode = HttpStatus.UNAUTHORIZED
                        return@flatMap exchange.response.setComplete()
                    }
                    val requestedUserId = extractUserIdFromRequest(exchange)

                    if (requestedUserId != tokenUserId) {
                        exchange.response.statusCode = HttpStatus.FORBIDDEN
                        return@flatMap exchange.response.setComplete()
                    }
                    forwardRequestToUserService(exchange, chain, accessToken)
                }
        }

    private fun extractBearerToken(exchange: ServerWebExchange): String? {
        val authorizationHeader = exchange.request.headers.getFirst(HttpHeaders.AUTHORIZATION)
        return if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            authorizationHeader.substring(7)
        } else null
    }

    private fun forwardRequestToUserService(exchange: ServerWebExchange, chain: GatewayFilterChain, token: String): Mono<Void> {
        val request = exchange.request.mutate()
            .header(HttpHeaders.AUTHORIZATION, "Bearer $token")
            .build()
        val mutatedExchange = exchange.mutate().request(request).build()

        return chain.filter(mutatedExchange)
    }

    private fun refreshAuthToken(exchange: ServerWebExchange, chain: GatewayFilterChain, oldToken: String): Mono<Void> {
        val refreshTokenRequest = mapOf("refreshToken" to oldToken)

        return webClient.build().post()
            .uri("${UrlConstants.AUTH_SERVICE_URL}/api/v1/token/refresh")
            .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
            .bodyValue(refreshTokenRequest)
            .retrieve()
            .onStatus({ status -> status.isError }) { response ->
                response.bodyToMono(String::class.java).flatMap { errorMessage ->
                    exchange.response.statusCode = response.statusCode()
                    exchange.response.headers[HttpHeaders.CONTENT_TYPE] = listOf(ContentType.APPLICATION_JSON.toString())
                    exchange.response.writeWith(Mono.just(exchange.response.bufferFactory().wrap(errorMessage.toByteArray())))
                        .then(Mono.error(Throwable("Error: $errorMessage")))
                }
            }
            .bodyToMono(Map::class.java)
            .flatMap { refreshResponse ->
                val newToken = refreshResponse["token"] as String?
                    ?: return@flatMap Mono.error(IllegalArgumentException("Failed to refresh token"))

                forwardRequestToUserService(exchange, chain, newToken)
            }
    }

    private fun decodeJwt(token: String): Claims {
        return Jwts.parserBuilder()
            .setSigningKey(Keys.hmacShaKeyFor(System.getenv("JWT_SECRET_KEY").toByteArray()))
            .build()
            .parseClaimsJws(token)
            .body
    }

    private fun extractUserIdFromRequest(exchange: ServerWebExchange): Int {
        val path = exchange.request.uri.path
        val match = Regex("/api/v1/user/(\\d+)").find(path)
        val value = match?.groups?.get(1)?.value
        return Integer.parseInt(value)
    }
}