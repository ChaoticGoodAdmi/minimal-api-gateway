package ru.ushakov.minimalauthgateway.filter

import com.nimbusds.common.contenttype.ContentType
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import ru.ushakov.minimalauthgateway.util.JsonBodyParser.parseJsonBody
import ru.ushakov.minimalauthgateway.util.UrlConstants
import java.nio.charset.StandardCharsets

@Component
class LoginFilter(
    private val webClient: WebClient.Builder
) : AbstractGatewayFilterFactory<Any>() {

    override fun apply(config: Any?): GatewayFilter =
        GatewayFilter { exchange: ServerWebExchange, _ ->
            exchange.request.body.collectList().flatMap { dataBuffers ->
                val requestBody = String(
                    dataBuffers.flatMap { it.asInputStream().readBytes().toList() }.toByteArray(),
                    StandardCharsets.UTF_8
                )
                val requestMap = parseJsonBody(requestBody)

                val username = requestMap["username"] as String?
                val password = requestMap["password"] as String?

                if (username == null || password == null) {
                    return@flatMap Mono.error(IllegalArgumentException("Invalid login data"))
                }

                webClient.build().post()
                    .uri("${UrlConstants.AUTH_SERVICE_URL}/api/v1/auth/login")
                    .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                    .bodyValue(
                        mapOf(
                            "username" to username,
                            "password" to password
                        )
                    )
                    .retrieve()
                    .onStatus({ it.isError }) { response ->
                        response.bodyToMono(String::class.java).flatMap { errorMessage ->
                            exchange.response.statusCode = response.statusCode()
                            exchange.response.headers[HttpHeaders.CONTENT_TYPE] = listOf(ContentType.APPLICATION_JSON.toString())
                            exchange.response.writeWith(Mono.just(exchange.response.bufferFactory().wrap(errorMessage.toByteArray())))
                                .then(Mono.error(Throwable("Error: $errorMessage")))
                        }
                    }
                    .bodyToMono(String::class.java)
                    .flatMap { authResponse ->
                        exchange.response.statusCode = HttpStatus.OK
                        exchange.response.headers[HttpHeaders.CONTENT_TYPE] = listOf(ContentType.APPLICATION_JSON.toString())
                        exchange.response.writeWith(
                            Mono.just(
                                exchange.response.bufferFactory().wrap(authResponse.toByteArray())
                            )
                        )
                    }
            }
        }
}