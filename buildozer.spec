[app]

# (str) Title of your application
title = Self-Hosted Cloud Storage

# (str) Package name
package.name = selfhostedcloudstorage

# (str) Package domain (needed for android/ios packaging)
package.domain = org.example

# (str) Source code where the main.py live
source.dir = android_app

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas

# (list) List of inclusions using pattern matching
#source.include_patterns = assets/*,images/*.png

# (list) Source files to exclude (let empty to not exclude anything)
#source.exclude_exts = spec

# (list) List of directory to exclude (let empty to not exclude anything)
#source.exclude_dirs = tests,bin

# (list) List of exclusions using pattern matching
#source.exclude_patterns = license,images/*/*.jpg

# (str) Application versioning (must be numeric)
version = 0.1

# (list) Kivy version to use
requirements = python3,kivy,cryptography,peewee

# (str) Presplash background color (for new android toolchain)
#android.presplash_color = #FFFFFF

# (str) Presplash animation using Lottie format.
#android.presplash_lottie = "path/to/lottie/animation.json"

# (str) Icon of the application
#icon.filename = %(source.dir)s/data/icon.png

# (str) Supported orientation (one of landscape, sensorLandscape, portrait, sensorPortrait)
orientation = portrait

# (list) Permissions
android.permissions = INTERNET, WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE

# (str) The Android arch to build for, one of armeabi-v7a, arm64-v8a, x86, x86_64
android.arch = arm64-v8a

# (int) Android API to use
android.api = 27

# (int) Minimum API required
android.minapi = 21

# (int) Android SDK version to use
#android.sdk = 24

# (str) Android NDK version to use
#android.ndk = 19b

# (str) Android NDK path. If not set, will be downloaded automatically
#android.ndk_path =

# (str) Android SDK path. If not set, will be downloaded automatically
#android.sdk_path =

# (str) Path to a custom keystore
#android.keystore =

# (str) Keystore password
#android.keystore_password =

# (str) Keystore alias
#android.keystore_alias =

# (str) Keystore alias password
#android.keystore_alias_password =

# (bool) Logcat filters to apply
#android.logcat_filters = *:S python:D

# (bool) Copy library files to project
#android.copy_libs = 1

# (str) The Android build tools version to use
#android.build_tools_version =

# (str) The name of the java class that will be called as the entry point
#android.entrypoint = org.kivy.android.PythonActivity

# (str) Kivy Android build directory
#android.build_dir = ./build-android

# (str) The name of the P4A bootstrap to use
#android.bootstrap = sdl2

# (bool) Whether to sign the APK
#android.release_build = 0

[buildozer]

# (int) Log level (0 = error, 1 = info, 2 = debug)
log_level = 2

# (int) Display warning messages
warn_on_root = 1