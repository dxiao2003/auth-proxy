package com.katapal.auth.proxy

import com.twitter.finagle.Http
import com.twitter.util.Await
import com.typesafe.config.ConfigFactory

/**
  * Created by David on 2/23/2016.
  */
object AuthProxyServer extends App {
  val config = ConfigFactory.load()
  val service = AuthProxyService(config)
  val server = Http.serve(config.getString("host") + ":" + config.getString("port"), service)
  Await.ready(server)
}
