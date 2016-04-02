package com.katapal.auth.proxy

import org.mockito.ArgumentMatcher

/**
  * Created by David on 2/23/2016.
  */

case class SatisfiesFunction[A](f: A => Boolean, msg: String) extends ArgumentMatcher[A] {
  def matches(x: Any): Boolean = f(x.asInstanceOf[A])
  override def toString: String = msg
}
