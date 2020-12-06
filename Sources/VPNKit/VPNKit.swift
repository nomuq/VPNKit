//
//    Copyright (c) 2020 Satish Babariya <satish.babariya@gmail.com>
//

import Foundation
import KeychainAccess
import NetworkExtension

public class VPNKit {
    public enum `Type` {
        case IPSec
        case IKEv2
    }

    public struct Account {
        public var id: UUID
        public var type: Type
        public var title: String
        public var server: String
        public var account: String?
        public var group: String?
        public var remoteID: String?
        public var alwaysOn: Bool

        public var password: String? {
            get {
                return VPNKit.keychain[id.uuidString]
            }
            set {
                guard let value = newValue else {
                    return
                }
                try? VPNKit.keychain.set(value, key: id.uuidString)
            }
        }

        public var secret: String? {
            get {
                return VPNKit.keychain["\(id.uuidString)psk"]
            }
            set {
                guard let value = newValue else {
                    return
                }
                try? VPNKit.keychain.set(value, key: "\(id.uuidString)psk")
            }
        }

        public var passwordReference: Data? {
            return VPNKit.keychain[attributes: id.uuidString]?.persistentRef
        }

        public var secretReference: Data? {
            guard
                let data = VPNKit.keychain[attributes: "\(id.uuidString)psk"]?.data, let value = String(data: data, encoding: .utf8), value.isEmpty == false
            else {
                return nil
            }
            return VPNKit.keychain[attributes: "\(id.uuidString)psk"]?.persistentRef
        }

        public init(id: UUID = UUID(), type: Type = .IPSec, title: String, server: String, account: String?, group: String?, remoteID: String?, alwaysOn: Bool = true, password: String?, secret: String?) {
            self.id = id
            self.type = type
            self.title = title
            self.server = server
            self.account = account
            self.group = group
            self.remoteID = remoteID
            self.alwaysOn = alwaysOn
            self.password = password
            self.secret = secret
        }
    }

    private static var keychain = Keychain(service: "com.satishbabariya.VPNKit")

    private var manager = NEVPNManager.shared()

    public var status: NEVPNStatus {
        return manager.connection.status
    }

    public static var `default` = VPNKit()

    public func connect(account: Account, result: @escaping (Error?) -> Void) {
        save(account: account) { [weak self] error in
            if error == nil {
                do {
                    try self?.manager.connection.startVPNTunnel()
                } catch {
                    NotificationCenter.default.post(name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
                    result(error)
                }
            } else {
                result(error)
            }
        }
    }

    public func disconnect() {
        manager.connection.stopVPNTunnel()
    }

    public func removeProfile(completion: @escaping (Error?) -> Void) {
        manager.removeFromPreferences { error in
            completion(error)
        }
    }
}

private extension VPNKit {
    func save(account: Account, completion: @escaping (Error?) -> Void) {
        #if targetEnvironment(simulator)
            assert(false, "simulators are not supported")
        #endif

        var pt: NEVPNProtocol

        switch account.type {
        case .IPSec:
            let p = NEVPNProtocolIPSec()
            p.useExtendedAuthentication = true
            p.localIdentifier = account.group ?? "VPN"
            p.remoteIdentifier = account.remoteID
            if let secret = account.secretReference {
                p.authenticationMethod = .sharedSecret
                p.sharedSecretReference = secret
            } else {
                p.authenticationMethod = .none
            }
            pt = p
        case .IKEv2:
            let p = NEVPNProtocolIKEv2()
            p.useExtendedAuthentication = true
            p.localIdentifier = account.group ?? "VPN"
            p.remoteIdentifier = account.remoteID
            if let secret = account.secretReference {
                p.authenticationMethod = .sharedSecret
                p.sharedSecretReference = secret
            } else {
                p.authenticationMethod = .none
            }
            p.deadPeerDetectionRate = NEVPNIKEv2DeadPeerDetectionRate.medium
            pt = p

            pt.disconnectOnSleep = !account.alwaysOn
            pt.serverAddress = account.server

            if let username = account.account {
                pt.username = username
            }

            if let password = account.passwordReference {
                pt.passwordReference = password
            }

            manager.localizedDescription = "VPNKit"
            manager.protocolConfiguration = pt
            manager.isEnabled = true

            // set on demand
            manager.onDemandRules = []
            manager.isOnDemandEnabled = false

            manager.saveToPreferences { error in
                completion(error)
            }
        }
    }
}
