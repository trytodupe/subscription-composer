#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static BOOL IsHTTPSURL(NSURL *url) {
    return [[url.scheme lowercaseString] isEqualToString:@"https"] && url.host.length > 0 &&
           url.user == nil;
}

static BOOL IsLoginCallback(NSURL *url) {
    if (![[url.scheme lowercaseString] isEqualToString:@"ikuuu"]) {
        return NO;
    }

    NSURLComponents *parts = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    if (parts == nil || parts.user != nil || parts.port != nil) {
        return NO;
    }

    NSString *raw = url.absoluteString;
    NSString *prefix = [url.scheme stringByAppendingString:@"://"];
    if (![raw hasPrefix:prefix]) {
        return NO;
    }

    if (parts.host != nil && [parts.host caseInsensitiveCompare:@"login"] == NSOrderedSame) {
        return parts.percentEncodedPath.length == 0 || [parts.percentEncodedPath isEqualToString:@"/"];
    }
    return parts.host.length == 0 && [parts.percentEncodedPath isEqualToString:@"/login"] &&
           [raw hasPrefix:[prefix stringByAppendingString:@"/"]];
}

static BOOL SaveCallback(NSString *callback, NSString *outputPath) {
    NSString *directory = [outputPath stringByDeletingLastPathComponent];
    NSFileManager *files = [NSFileManager defaultManager];
    NSString *current = [directory hasPrefix:@"/"] ? @"/" : @".";
    for (NSString *component in directory.pathComponents) {
        if ([component isEqualToString:@"/"] || [component isEqualToString:@"."]) {
            continue;
        }
        current = [current stringByAppendingPathComponent:component];
        BOOL isDirectory = NO;
        if ([files fileExistsAtPath:current isDirectory:&isDirectory]) {
            if (!isDirectory) {
                return NO;
            }
        } else if (![files createDirectoryAtPath:current
                    withIntermediateDirectories:NO
                                     attributes:@{NSFilePosixPermissions: @0700}
                                          error:NULL]) {
            return NO;
        }
    }

    NSString *pattern = [directory stringByAppendingPathComponent:@".ikuuu-login-XXXXXX"];
    char *temporaryPath = strdup(pattern.fileSystemRepresentation);
    if (temporaryPath == NULL) {
        return NO;
    }
    int fd = mkstemp(temporaryPath);
    if (fd < 0) {
        free(temporaryPath);
        return NO;
    }

    NSData *data = [callback dataUsingEncoding:NSUTF8StringEncoding];
    const char *bytes = data.bytes;
    NSUInteger remaining = data.length;
    BOOL ok = data != nil && fchmod(fd, 0600) == 0;
    while (ok && remaining > 0) {
        ssize_t written = write(fd, bytes, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            ok = NO;
            break;
        }
        bytes += written;
        remaining -= (NSUInteger)written;
    }
    if (ok && fsync(fd) != 0) {
        ok = NO;
    }
    if (close(fd) != 0) {
        ok = NO;
    }
    // A hard link publishes the completed file atomically without replacing an existing callback.
    if (ok && link(temporaryPath, outputPath.fileSystemRepresentation) != 0) {
        ok = NO;
    }
    unlink(temporaryPath);
    free(temporaryPath);
    return ok;
}

@interface LoginWindow : NSObject <NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) WKWebView *webView;
@property(nonatomic, strong) NSURL *loginURL;
@property(nonatomic, copy) NSString *outputPath;
@end

@implementation LoginWindow

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 900, 720)
                                             styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                                       NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                               backing:NSBackingStoreBuffered
                                                 defer:NO];
    self.window.title = @"ikuuu sign-in";
    self.window.delegate = self;

    self.webView = [[WKWebView alloc] initWithFrame:self.window.contentView.bounds];
    self.webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    self.webView.navigationDelegate = self;
    self.webView.UIDelegate = self;
    [self.window.contentView addSubview:self.webView];
    [self.window center];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self.webView loadRequest:[NSURLRequest requestWithURL:self.loginURL]];
}

- (void)windowWillClose:(NSNotification *)notification {
    (void)notification;
    puts("Login window closed without a callback.");
    exit(EXIT_FAILURE);
}

- (void)captureCallback:(NSURL *)url {
    if (SaveCallback(url.absoluteString, self.outputPath)) {
        puts("Login callback saved.");
        exit(EXIT_SUCCESS);
    }
    puts("Could not save login callback.");
    exit(EXIT_FAILURE);
}

- (void)webView:(WKWebView *)webView
    decidePolicyForNavigationAction:(WKNavigationAction *)navigationAction
                   decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    (void)webView;
    NSURL *url = navigationAction.request.URL;
    if (IsLoginCallback(url)) {
        decisionHandler(WKNavigationActionPolicyCancel);
        [self captureCallback:url];
        return;
    }
    decisionHandler(IsHTTPSURL(url) ? WKNavigationActionPolicyAllow : WKNavigationActionPolicyCancel);
}

- (WKWebView *)webView:(WKWebView *)webView
    createWebViewWithConfiguration:(WKWebViewConfiguration *)configuration
               forNavigationAction:(WKNavigationAction *)navigationAction
                    windowFeatures:(WKWindowFeatures *)windowFeatures {
    (void)configuration;
    (void)windowFeatures;
    NSURL *url = navigationAction.request.URL;
    if (IsLoginCallback(url)) {
        [self captureCallback:url];
    } else if (IsHTTPSURL(url)) {
        [webView loadRequest:navigationAction.request];
    }
    return nil;
}

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 5) {
            puts("Usage: ikuuu-login --url HTTPS_LOGIN_URL --output PRIVATE_CALLBACK_FILE");
            return EXIT_FAILURE;
        }
        NSString *urlArgument = nil;
        NSString *outputArgument = nil;
        for (int i = 1; i < argc; i += 2) {
            NSString *flag = [NSString stringWithUTF8String:argv[i]];
            NSString *value = [NSString stringWithUTF8String:argv[i + 1]];
            if ([flag isEqualToString:@"--url"] && urlArgument == nil) {
                urlArgument = value;
            } else if ([flag isEqualToString:@"--output"] && outputArgument == nil) {
                outputArgument = value;
            } else {
                puts("Invalid arguments. Use --url and --output once each.");
                return EXIT_FAILURE;
            }
        }

        NSURL *loginURL = [NSURL URLWithString:urlArgument ?: @""];
        if (!IsHTTPSURL(loginURL) || outputArgument.length == 0 ||
            [outputArgument hasSuffix:@"/"]) {
            puts("Provide an HTTPS login URL and an output file path.");
            return EXIT_FAILURE;
        }

        NSApplication *application = [NSApplication sharedApplication];
        application.activationPolicy = NSApplicationActivationPolicyRegular;
        LoginWindow *loginWindow = [LoginWindow new];
        loginWindow.loginURL = loginURL;
        loginWindow.outputPath = [outputArgument stringByStandardizingPath];
        application.delegate = loginWindow;
        [application run];
        return EXIT_FAILURE;
    }
}
