package com.katapal.auth.proxy

import com.twitter.finagle.Redis
import com.twitter.finagle.redis.util.{CBToString, StringToChannelBuffer}
import com.twitter.util.Future
import com.typesafe.config.Config

/**
  * Created by David on 2/23/2016.
  */

case class CacheClient(config: Config) {
  val clientAddress = config.getString("cache-server")
  val client = Redis.client.newRichClient(clientAddress)

  def get(key: String): Future[Option[String]] = {
    client.get(StringToChannelBuffer(key)).map(result => result.map(buf => CBToString(buf)))
  }

  def set(key: String, value: String): Future[Unit] = {
    client.set(StringToChannelBuffer(key), StringToChannelBuffer(value))
  }
}

