package ru.ushakov.minimalauthgateway.util

object UrlConstants {
    val AUTH_SERVICE_URL: String = System.getenv("AUTH_SERVICE_URL") ?: "http://auth-service-svc"
    val USER_SERVICE_URL: String = System.getenv("USER_SERVICE_URL") ?: "http://user-service-svc"
}