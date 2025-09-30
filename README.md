# Fingerprint Orientation Auth (Android 15)

An Android app (Kotlin) that differentiates fingerprint usage based on touch orientation (horizontal vs vertical) in addition to standard biometric authentication. Authentication succeeds only when BOTH the biometric matches and the captured touch orientation matches the orientation registered for that finger.

Note: Android does not expose which enrolled fingerprint was used nor any raw fingerprint images. This app does not attempt to read fingerprint templates. It only uses standard BiometricPrompt success/failure and independently captured touch orientation metadata.

## Requirements
- Android Studio (Android Gradle Plugin 8.6+)
- Android SDK 35 (Android 15) for compile/target
- Min SDK 28 (Android 9)

## Key Features
- Touch Capture Phase: Captures x/y from on-screen touch gestures and classifies orientation: HORIZONTAL, VERTICAL, or OTHER.
- Biometric Authentication Phase: Uses BiometricPrompt to perform strong biometric auth.
- Orientation Verification Phase: Compares the captured touch orientation against registered orientation metadata; only then confirms auth.
- Registration: Requires the same finger to be placed twice: horizontal and vertical (orientation metadata only).
- Storage: Stores only orientation flags (horizontal/vertical) in EncryptedSharedPreferences.
- UI: Two tabs — Registration and Authentication.
- Tests: Unit tests for orientation classification logic.

## Project Structure
- app/src/main/java/com/example/fporientation/
  - MainActivity, MainPagerAdapter
  - ui/
    - RegistrationFragment, AuthFragment, TouchCaptureView
  - biometric/
    - BiometricHelper
  - storage/
    - OrientationStore (EncryptedSharedPreferences)
  - util/
    - OrientationCalculator (orientation logic)
- app/src/test/java/... OrientationCalculatorTest

## Orientation Classification
We classify orientation from the gesture angle (degrees):
- HORIZONTAL: angle in [-30..30] or [150..180] or [-180..-150]
- VERTICAL: angle in [60..120] or [-120..-60]
- OTHER: otherwise

Pseudo:
- dx = endX - startX
- dy = endY - startY
- angle = degrees(atan2(dy, dx))

## Security & Privacy
- Uses BiometricPrompt with BIOMETRIC_STRONG.
- Stores only orientation metadata (booleans for horizontal/vertical) encrypted via EncryptedSharedPreferences.
- Does not store any fingerprint images or templates.
- Shows UI text to inform the user.

## Building
- Open the project in Android Studio, let it sync dependencies.
- Build/Run on a device with fingerprint hardware and at least Android 9.

If building via CLI:
- Ensure a local Gradle is installed (wrapper JAR is not included here).
- From project root: `gradle assembleDebug`

## Using the App
1. Registration tab:
   - Follow instructions. Drag slightly horizontally and lift; authenticate with fingerprint.
   - Then drag vertically and lift; authenticate again. Both orientations should be registered.
2. Authentication tab:
   - Drag in either the registered horizontal or vertical orientation; authenticate.
   - Success only when both biometric is successful and the orientation matches a registered one.

## Limitations
- The system does not reveal which specific fingerprint was used; success from BiometricPrompt only indicates a valid enrolled biometric. This app enforces orientation matching as an additional factor but cannot verify that the same finger was used beyond biometric success.
- The touch capture view is an on-screen approximation and may not precisely match a physical or in-display sensor area; adapt the UI overlay if targeting devices with specific sensor locations.
