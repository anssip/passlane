.PHONY: ios-framework

# Build PasslaneCore.xcframework + the generated Swift module the iOS app
# consumes (passlane#45). Output lands in target/ios/ — see
# docs/features/ios-framework.md for prerequisites and consumer wiring.
ios-framework:
	sh crates/passlane-ffi/build-ios.sh
