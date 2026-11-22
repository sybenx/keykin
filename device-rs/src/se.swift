// The Secure Enclave part of `keykin` (chip.rs). Only this file talks to the chip.
//
// The chip holds a P-256 key-agreement key that never leaves it. CryptoKit hands back a blob that only
// this Mac's chip can use, so no keychain item and no Apple developer signing are needed. Every use asks
// for Touch ID (or the login password, with no sensor), with the reason the caller gives.

import CryptoKit
import Foundation
import LocalAuthentication

private func copyOut(_ d: Data, _ out: UnsafeMutablePointer<UInt8>, _ cap: Int, _ len: UnsafeMutablePointer<Int>) -> Int32 {
    if d.count > cap { return 3 }
    d.copyBytes(to: out, count: d.count)
    len.pointee = d.count
    return 0
}

/// 0 when this Mac has a Secure Enclave.
@_cdecl("kk_se_available")
public func kk_se_available() -> Int32 {
    SecureEnclave.isAvailable ? 0 : 1
}

/// A new chip key that asks for the person on every use. Writes its blob and its public key (65 bytes, X9.63).
/// 0 ok, 2 the chip said no, 3 a buffer is too small.
@_cdecl("kk_se_new")
public func kk_se_new(_ blob: UnsafeMutablePointer<UInt8>, _ blobCap: Int, _ blobLen: UnsafeMutablePointer<Int>,
                      _ pub: UnsafeMutablePointer<UInt8>) -> Int32 {
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                   [.privateKeyUsage, .userPresence], &err) else { return 2 }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        let p = k.publicKey.x963Representation
        if p.count != 65 { return 2 }
        p.copyBytes(to: pub, count: 65)
        return copyOut(k.dataRepresentation, blob, blobCap, blobLen)
    } catch { return 2 }
}

/// ECDH between the chip key in `blob` and `peer` (65 bytes, X9.63): writes the 32-byte shared x. Asks for the
/// person first, saying `reason` ("keykin wants to <reason>"). 0 ok, 1 they said no or it timed out, 2 the chip
/// or the blob failed.
@_cdecl("kk_se_ecdh")
public func kk_se_ecdh(_ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ peer: UnsafePointer<UInt8>,
                       _ reason: UnsafePointer<CChar>, _ out: UnsafeMutablePointer<UInt8>) -> Int32 {
    let ctx = LAContext()
    ctx.localizedReason = String(cString: reason)
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(bytes: blob, count: blobLen),
                                                                authenticationContext: ctx)
        let p = try P256.KeyAgreement.PublicKey(x963Representation: Data(bytes: peer, count: 65))
        let s = try k.sharedSecretFromKeyAgreement(with: p)
        let bytes = s.withUnsafeBytes { Data($0) }
        if bytes.count != 32 { return 2 }
        bytes.copyBytes(to: out, count: 32)
        return 0
    } catch let e as LAError where [.userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback].contains(e.code) {
        return 1
    } catch {
        let ns = error as NSError
        // CryptoKit wraps the person's No as a Security error (errSecUserCanceled / errSecAuthFailed).
        if ns.code == -128 || ns.code == -25293 || ns.code == Int(errSecUserCanceled) { return 1 }
        return 2
    }
}
