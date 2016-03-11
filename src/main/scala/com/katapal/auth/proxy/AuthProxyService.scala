package com.katapal.auth.proxy

import com.katapal.auth.jwt.JWTVerifier
import com.twitter.finagle.{Http, Service, http}

import com.typesafe.config.Config
import java.net.URL



object AuthService {
  def apply(config: Config) = {
    val authURL = new URL(config.getString("auth-server"))
    val dest = authURL.getProtocol + "://" + authURL.getAuthority
    Http.client.newService(dest)
  }
}

object AuthProxyService {
  def apply(config: Config): Service[http.Request, http.Response] = {
    val cacheClient = CacheClient(config)
    val authService = AuthService(config)
    val tokenVerifier = new JWTVerifier(config)
    val authProxyFilter = new AuthProxyFilter(config, cacheClient, tokenVerifier, authService)
    val httpReverseProxy = Http.client.newService(config.getString("dest"))

    authProxyFilter.andThen(httpReverseProxy)
  }
}
