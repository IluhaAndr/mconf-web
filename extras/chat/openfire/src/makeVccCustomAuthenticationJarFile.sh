#/bin/bash

# Directory of Source Code of Openfire Project
OPENFIRE_DIR=~/workspace/openfire
# Global Dir
GLOBAL_DIR=~/workspace/global2

# Compile
pushd $OPENFIRE_DIR/build
ant
popd

# Copy src
pushd $OPENFIRE_DIR/src/java/org/jivesoftware/openfire
cp auth/VccCustomAuthProvider.java $GLOBAL_DIR/extras/chat/openfire/src/java/org/jivesoftware/openfire/auth
cp group/VccCustomGroupProvider.java $GLOBAL_DIR/extras/chat/openfire/src/java/org/jivesoftware/openfire/group
popd

# Make jar file and deploy
pushd $OPENFIRE_DIR/work/classes
jar cf vccCustomAuthentication.jar org/jivesoftware/openfire/auth/VccCustomAuthProvider* org/jivesoftware/openfire/group/VccCustomGroupProvider.class
cp vccCustomAuthentication.jar $GLOBAL_DIR/extras/chat/openfire/installation/
sudo cp vccCustomAuthentication.jar /usr/share/openfire/lib
popd
