package ru.ushakov.minimalauthgateway.util

import org.json.JSONObject

object JsonBodyParser {

    fun parseJsonBody(body: String): Map<String, Any> {
        val jsonObject = JSONObject(body)
        val map = mutableMapOf<String, Any>()

        jsonObject.keys().forEach { key ->
            map[key] = jsonObject[key]
        }
        return map
    }
}
