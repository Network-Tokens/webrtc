vars = {
  # Use this googlecode_url variable only if there is an internal mirror for it.
  # If you do not know, use the full path while defining your new deps entry.
  "googlecode_url": "http://%s.googlecode.com/svn",
  "chromium_trunk" : "http://src.chromium.org/svn/trunk",
  "chromium_revision": "98568",
  "libjingle_revision": "85",
}

# NOTE: Prefer revision numbers to tags.
deps = {
  "trunk/build":
    Var("chromium_trunk") + "/src/build@" + Var("chromium_revision"),

  "trunk/testing":
    Var("chromium_trunk") + "/src/testing@" + Var("chromium_revision"),

  "trunk/testing/gtest":
    (Var("googlecode_url") % "googletest") + "/trunk@573",

  "trunk/testing/gmock":
    (Var("googlecode_url") % "googlemock") + "/trunk@386",

  "trunk/tools/gyp":
    (Var("googlecode_url") % "gyp") + "/trunk@1012",

  "trunk/third_party/protobuf/":
    Var("chromium_trunk") + "/src/third_party/protobuf@" + Var("chromium_revision"),

  # TODO(andrew): return to the webm git repository when possible.
  "trunk/third_party/libvpx/source/libvpx":
    Var("chromium_trunk") + "/deps/third_party/libvpx/source/libvpx@98040",
    #"git://review.webmproject.org/libvpx.git@v0.9.7-p1",

  "trunk/third_party/libjpeg_turbo/":
    Var("chromium_trunk") + "/deps/third_party/libjpeg_turbo@95800",

  "trunk/third_party/libjpeg/":
    Var("chromium_trunk") + "/src/third_party/libjpeg@" + Var("chromium_revision"),

  "trunk/third_party/yasm/":
    Var("chromium_trunk") + "/src/third_party/yasm@" + Var("chromium_revision"),

  "trunk/third_party/expat/":
    Var("chromium_trunk") + "/src/third_party/expat@" + Var("chromium_revision"),

  "trunk/third_party/libjingle/":
    Var("chromium_trunk") + "/src/third_party/libjingle@" + Var("chromium_revision"),

  "trunk/third_party/google-gflags/src":
    (Var("googlecode_url") % "google-gflags") + "/trunk/src@45",

  "trunk/third_party/libjingle/source":
    (Var("googlecode_url") % "libjingle") + "/trunk@" + Var("libjingle_revision"),

  "trunk/third_party/yasm/source/patched-yasm":
    Var("chromium_trunk") + "/deps/third_party/yasm/patched-yasm@73761",
  # Used by libjpeg-turbo
  "trunk/third_party/yasm/binaries":
    Var("chromium_trunk") + "/deps/third_party/yasm/binaries@74228",

  "trunk/third_party/jsoncpp/":
    "http://jsoncpp.svn.sourceforge.net/svnroot/jsoncpp/trunk/jsoncpp@246",
}

deps_os = {
  "win": {
    "trunk/third_party/cygwin/":
      Var("chromium_trunk") + "/deps/third_party/cygwin@66844",
  }
}

hooks = [
  {
    # Create a supplement.gypi file under trunk/.  This file will be picked up
    # by gyp and we use it to set Chromium related variables (inside_chromium_build)
    # to 0 and enable the standalone build.
    "pattern": ".",
    "action": ["python", "trunk/tools/create_supplement_gypi.py", "trunk/src/supplement.gypi"],
  },
  # A change to a .gyp, .gypi, or to GYP itself should run the generator.
  {
    "pattern": ".",
    "action": ["python", "trunk/build/gyp_chromium", "--depth=trunk", "trunk/webrtc.gyp"],
  },
]

