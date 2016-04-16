package com.katapal.auth.proxy

import com.twitter.finagle.Redis
import com.twitter.finagle.redis.util.{CBToString, StringToChannelBuffer}
import com.twitter.util.{Await, Future}
import com.typesafe.config.Config

/**
  * Created by David on 2/23/2016.
  */

case class CacheClient(config: Config) {
  private val clientAddress = config.getString("redis.host") + ":" + config.getString("redis.port")
  private val client = Redis.client.newRichClient(clientAddress)
  Await.result(client.auth(StringToChannelBuffer(config.getString("redis.password"))))
  if (config.hasPath("redis.database"))
    Await.result(client.select(config.getInt("redis.database")))
  private val expirationMillis = config.getDuration("expiration").toMillis

  def get(key: String): Future[Option[String]] = {
    client.get(StringToChannelBuffer(key)).map(result => result.map(buf => CBToString(buf)))
  }

  def set(key: String, value: String): Future[Unit] = {
    client.pSetEx(StringToChannelBuffer(key), expirationMillis, StringToChannelBuffer(value))
  }
}

