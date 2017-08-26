ARCHS = armv7 armv7s arm64
SDKVERSION = $(xcrun --sdk iphoneos --show-sdk-version)

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ipaspect
ipaspect_FILES = Tweak.xm

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
