package ru.ushakov.minimalauthgateway

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class MinimalAuthGatewayApplication

fun main(args: Array<String>) {
    runApplication<MinimalAuthGatewayApplication>(*args)
}
