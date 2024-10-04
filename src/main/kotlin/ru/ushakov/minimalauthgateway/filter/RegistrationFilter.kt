package ru.ushakov.minimalauthgateway.filter


import com.nimbusds.common.contenttype.ContentType
import org.json.JSONObject
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.reactive.function.client.WebClient
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import ru.ushakov.minimalauthgateway.util.JsonBodyParser
import ru.ushakov.minimalauthgateway.util.UrlConstants
import java.nio.charset.StandardCharsets

@Component
class RegistrationFilter(
    private val webClient: WebClient.Builder
) : AbstractGatewayFilterFactory<Any>() {

    override fun apply(config: Any?): GatewayFilter =
        GatewayFilter { exchange: ServerWebExchange, _ : GatewayFilterChain ->
            exchange.request.body.collectList().flatMap { dataBuffers ->
                val requestBody = String(
                    dataBuffers.flatMap { it.asInputStream().readBytes().toList() }.toByteArray(),
                    StandardCharsets.UTF_8
                )
                val requestMap = JsonBodyParser.parseJsonBody(requestBody)

                val username = requestMap["username"] as String?
                val password = requestMap["password"] as String?
                val email = requestMap["email"] as String?
                val firstName = requestMap["firstName"] as String?
                val lastName = requestMap["lastName"] as String?
                val phone = requestMap["phone"] as String?

                if (username == null || password == null || email == null) {
                    return@flatMap Mono.error(IllegalArgumentException("Invalid registration data"))
                }

                webClient.build().post()
                    .uri("${UrlConstants.AUTH_SERVICE_URL}/api/v1/auth/register")
                    .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                    .bodyValue(
                        mapOf(
                            "username" to username,
                            "password" to password,
                            "email" to email
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
                    .bodyToMono(Map::class.java)
                    .flatMap { authResponse ->
                        val userId = authResponse["userId"] as Int?

                        if (userId == null || firstName == null || lastName == null || phone == null) {
                            return@flatMap Mono.error(IllegalArgumentException("Missing user data"))
                        }

                        webClient.build().post()
                            .uri("${UrlConstants.USER_SERVICE_URL}/api/v1/user")
                            .header(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                            .bodyValue(
                                mapOf(
                                    "id" to userId,
                                    "firstName" to firstName,
                                    "lastName" to lastName,
                                    "phone" to phone
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
                    }
                    .flatMap { userResponse ->
                        exchange.response.statusCode = HttpStatus.OK
                        exchange.response.headers[HttpHeaders.CONTENT_TYPE] = listOf(ContentType.APPLICATION_JSON.toString())
                        exchange.response.writeWith(
                            Mono.just(
                                exchange.response.bufferFactory().wrap(userResponse.toByteArray())
                            )
                        )
                    }
            }
        }
}