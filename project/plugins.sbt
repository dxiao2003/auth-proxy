logLevel := Level.Warn

resolvers += "Era7 maven releases" at "https://s3-eu-west-1.amazonaws.com/releases.era7.com"

addSbtPlugin("ohnosequences" % "sbt-s3-resolver" % "0.14.0")

addSbtPlugin("com.typesafe.sbt" % "sbt-native-packager" % "1.1.0-RC2")
