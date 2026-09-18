//
//  FlutterSecureStorageDarwinPlugin.swift
//

import LocalAuthentication
import Security
#if os(iOS)
import Flutter
import UIKit
#else
import AppKit
import FlutterMacOS
#endif

public class FlutterSecureStorageDarwinPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private let flutterSecureStorageManager: FlutterSecureStorage = FlutterSecureStorage()
    private var secStoreAvailabilitySink: FlutterEventSink?
    private let serialExecutionQueue = DispatchQueue(label: "flutter_secure_storage_service")

    public static func register(with registrar: FlutterPluginRegistrar) {
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif

        let channel = FlutterMethodChannel(name: "plugins.it_nomads.com/flutter_secure_storage", binaryMessenger: messenger)
        let eventChannel = FlutterEventChannel(name: "plugins.it_nomads.com/flutter_secure_storage/events", binaryMessenger: messenger)
        let instance = FlutterSecureStorageDarwinPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        registrar.addApplicationDelegate(instance)
        eventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        func handleResult(_ value: Any?) {
            DispatchQueue.main.async {
                result(value)
            }
        }

        serialExecutionQueue.async {
            switch call.method {
            case "read":
                self.read(call, handleResult)
            case "write":
                self.write(call, handleResult)
            case "delete":
                self.delete(call, handleResult)
            case "deleteAll":
                self.deleteAll(call, handleResult)
            case "readAll":
                self.readAll(call, handleResult)
            case "containsKey":
                self.containsKey(call, handleResult)
            case "isProtectedDataAvailable":
                DispatchQueue.main.async {
                    #if os(iOS)
                    result(UIApplication.shared.isProtectedDataAvailable)
                    #else
                    if #available(macOS 12.0, *) {
                        result(NSApplication.shared.isProtectedDataAvailable)
                    } else {
                        result(true)
                    }
                    #endif
                }
            default:
                handleResult(FlutterMethodNotImplemented)
            }
        }
    }

    public func onListen(withArguments arguments: Any?,
                         eventSink: @escaping FlutterEventSink) -> FlutterError? {
        self.secStoreAvailabilitySink = eventSink
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        self.secStoreAvailabilitySink = nil
        return nil
    }

    #if os(iOS)
    public func applicationProtectedDataDidBecomeAvailable(_ application: UIApplication) {
        secStoreAvailabilitySink?(true)
    }

    public func applicationProtectedDataWillBecomeUnavailable(_ application: UIApplication) {
        secStoreAvailabilitySink?(false)
    }
    #else
    @objc @available(macOS 12.0, *)
    public func applicationProtectedDataDidBecomeAvailable(_ notification: Notification) {
        secStoreAvailabilitySink?(true)
    }

    @objc @available(macOS 12.0, *)
    public func applicationProtectedDataWillBecomeUnavailable(_ notification: Notification) {
        secStoreAvailabilitySink?(false)
    }
    #endif

    private func read(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "read requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.read(params: params)
        handleResponse(response, result)
    }

    private func write(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, value) = parseCall(call)
        guard let _ = params.key, let value = value else {
            result(FlutterError(code: "Missing Parameter", message: "write requires key and value parameters", details: nil))
            return
        }

        let response = flutterSecureStorageManager.write(params: params, value: value)
        handleResponse(response, result)
    }

    private func delete(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "delete requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.delete(params: params)
        handleResponse(response, result)
    }

    private func deleteAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        let response = flutterSecureStorageManager.deleteAll(params: params)
        handleResponse(response, result)
    }

    private func readAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        let response = flutterSecureStorageManager.readAll(params: params)
        handleResponse(response, result)
    }

    private func containsKey(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "containsKey requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.containsKey(params: params)

        switch response {
        case .success(let exists):
            result(exists)
        case .failure(let error):
            if error.status == errSecUserCanceled {
                result(FlutterError(code: "BIOMETRIC_CANCELED", message: "BIOMETRIC_CANCELED: User canceled authentication", details: error.status))
                return
            }
            let errorMessage = SecCopyErrorMessageString(error.status, nil) ?? "Unknown security result code: \(error.status)" as CFString
            result(FlutterError(code: "Unexpected security result code", message: errorMessage as String, details: error.status))
        }
    }

    private func parseCall(_ call: FlutterMethodCall) -> (KeychainQueryParameters, String?) {
        let arguments = call.arguments as! [String: Any?]
        let options = arguments["options"] as? [String: Any?] ?? [:]

        let value = arguments["value"] as? String

        var parameters = KeychainQueryParameters(
            key: arguments["key"] as? String,
            accessGroup: options["groupId"] as? String,
            service: options["accountName"] as? String,
            isSynchronizable: (options["synchronizable"] as? String).flatMap { Bool($0) },
            accessibilityLevel: options["accessibility"] as? String,
            usesDataProtectionKeychain: (options["usesDataProtectionKeychain"] as? String).flatMap { Bool($0) } ?? true,
            shouldReturnData: true, // Default behavior for most operations.
            itemLabel: options["label"] as? String,
            itemDescription: options["description"] as? String,
            itemComment: options["comment"] as? String,
            isHidden: (options["isHidden"] as? String).flatMap { Bool($0) },
            isPlaceholder: (options["isPlaceholder"] as? String).flatMap { Bool($0) },
            shouldReturnPersistentReference: (options["persistentReference"] as? String).flatMap { Bool($0) },
            authenticationUIBehavior: options["authenticationUIBehavior"] as? String,
            accessControlFlags: options["accessControlFlags"] as? String,
            useSecureEnclave: (options["useSecureEnclave"] as? String).flatMap { Bool($0) }
        )

        // One LAContext per method call. `localizedReason` must be set or the
        // system prompt is suppressed. Duration 0 (default) does not reuse a
        // prior evaluation across later read/write calls.
        if needsAuthenticationContext(parameters) {
            if #available(iOS 9.0, macOS 10.12, *) {
                let context = LAContext()
                context.interactionNotAllowed = false
                context.localizedReason = promptReason(from: options, parameters: parameters)
                let cancelTitle = (options["localizedCancelTitle"] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if let cancelTitle, !cancelTitle.isEmpty {
                    context.localizedCancelTitle = cancelTitle
                }
                let reuse = (options["biometricReuseDurationSeconds"] as? String)
                    .flatMap { TimeInterval($0) } ?? 0
                context.touchIDAuthenticationAllowableReuseDuration = min(max(reuse, 0), 300)
                parameters.authenticationContext = context
            }
        }

        return (parameters, value)
    }

    /// `kSecUseAuthenticationContext` when this call uses access control or Secure Enclave.
    private func needsAuthenticationContext(_ parameters: KeychainQueryParameters) -> Bool {
        if parameters.useSecureEnclave == true {
            return true
        }
        let flags = parameters.accessControlFlags ?? ""
        return flags.contains("biometry") || flags.contains("userPresence")
    }

    /// `LAContext.localizedReason` is required for the system prompt to appear.
    private func promptReason(from options: [String: Any?], parameters: KeychainQueryParameters) -> String {
        let candidates: [String?] = [
            options["description"] as? String,
            parameters.itemDescription,
            options["label"] as? String,
            parameters.itemLabel,
        ]
        for candidate in candidates {
            let trimmed = candidate?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !trimmed.isEmpty {
                return trimmed
            }
        }
        return "Authenticate to access"
    }

    private func handleResponse(_ response: FlutterSecureStorageResponse, _ result: @escaping FlutterResult) {
        let status = response.status
        if status != noErr {
            if status == errSecUserCanceled {
                result(FlutterError(code: "BIOMETRIC_CANCELED", message: "BIOMETRIC_CANCELED: User canceled authentication", details: status))
                return
            }
            let errorMessage: String
            if #available(iOS 11.3, *) {
                if let errMsg = SecCopyErrorMessageString(status, nil) {
                    errorMessage = "Code: \(status), Message: \(errMsg)"
                } else {
                    errorMessage = "Unknown security result code: \(status)"
                }
            } else {
                errorMessage = "Unknown security result code: \(status)"
            }
            result(FlutterError(code: "Unexpected security result code", message: errorMessage as String, details: status))
        } else {
            result(response.value)
        }
    }
}
