#!/bin/bash
# just added a simple var when ppl ask me to build multiple IPAs
# thanks to @matteyeux, @cheesecakeufo, @DakuSuta777, @nullriver
# (Terminal)
# cd (sajlbrk folder)
# chmod +x make_ipa.sh
# make_ipa.sh

APP=sajlbrk
$(which xcodebuild) clean build CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" -sdk `xcrun --sdk iphoneos --show-sdk-path` -arch arm64
mv build/Release-iphoneos/$APP.app $APP.app
mkdir Payload
mv $APP.app Payload/$APP.app
zip -r9 $APP.ipa Payload/$APP.app
rm -rf build Payload
