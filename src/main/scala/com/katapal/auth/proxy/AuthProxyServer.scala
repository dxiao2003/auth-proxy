package com.katapal.auth.proxy

import com.twitter.finagle.Http
import com.twitter.util.Await
import com.typesafe.config.{Config, ConfigFactory}

/**
  * Created by David on 2/23/2016.
  */
object AuthProxyServer extends App {
  def validateConfig(baseConfig: Config) = {
    baseConfig.checkValid(ConfigFactory.defaultReference(), "auth-proxy")
    baseConfig.getConfig("auth-proxy")
  }

  def startServer(config: Config) = {
    val service = AuthProxyService(config)
    Http.serve(config.getString("host") + ":" + config.getString("port"), service)
  }

  val config = ConfigFactory.load()
  val proxyConfig = validateConfig(config).withFallback(config)
  val server = startServer(proxyConfig)
  Await.ready(server)
}
