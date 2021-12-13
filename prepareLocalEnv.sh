#!/bin/sh
set -e

oldDir=`pwd`
cd `dirname "$0"`/java
./mvnw package
cp ./target/evilfactory-1.0-SNAPSHOT.jar ../
cd "$oldDir"
