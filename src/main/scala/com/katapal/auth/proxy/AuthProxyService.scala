package com.katapal.auth.proxy

import com.katapal.auth.jwt.JWTVerifier
import com.twitter.finagle.{Http, Service, http}

import com.typesafe.config.Config
import java.net.URL


/**
  * This service calls the server actually responsible for doing authentication and returning a valid token.
  */
object AuthService {
  def apply(config: Config) = {
    val authURL = new URL(config.getString("auth-url"))
    Http.client.newService(authURL.getAuthority)
  }
}

object AuthProxyService {
  def apply(config: Config): Service[http.Request, http.Response] = {
    val cacheClient = CacheClient(config)
    val authService = AuthService(config)
    val tokenVerifier = new JWTVerifier(config.getConfig("jwt"))
    val authProxyFilter = new AuthProxyFilter(config, cacheClient, tokenVerifier, authService)
    val httpReverseProxy = Http.client.newService(config.getString("dest"))

    authProxyFilter.andThen(httpReverseProxy)
  }
}
