//
//  ContentView.swift
//  PracticeApp
//
//  Created by 김인섭 on 2/23/24.
//
import SwiftUI
import WalletCore

struct ContentView: View {
    var body: some View {
        Button(action: {
            
            //MARK: - PrivateKey
            let privateKeyString = """
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIALWQXPzLbZOwBO2iM6yWGu+DPP170wQTNf8v+RGBzu/oAcGBSuBBAAKoUQDQgAEphNA43z0jLJmNAtJiXXnY6kHreUihBRr6+XqXJTaZeybUjnmQxWe9cOFMjMkcA5dAAXHjPDdoTOqrsagIoGqIg==
            -----END EC PRIVATE KEY-----
            """
            
            guard let privateKey = privateKeyFrom(keyString: privateKeyString) else {return}
            print("PrivateKey: ", privateKey)
            
            //MARK: - Signature
            let diget = Hash.sha256(data: "hello".data(using: .utf8) ?? Data())
            guard let signature = privateKey.signAsDER(digest: diget)
            else { return }
            print("Signature: ", signature.base64EncodedString())
            
            //MARK: - PublicKey
            let publicKeyString = """
            -----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEphNA43z0jLJmNAtJiXXnY6kHreUihBRr6+XqXJTaZeybUjnmQxWe9cOFMjMkcA5dAAXHjPDdoTOqrsagIoGqIg==
            -----END PUBLIC KEY-----
            """
            
            guard let publicKey = publicKeyFrom(keyString: publicKeyString) else {return}
            print("PublicKey: ", publicKey)
            
            print("verify 결과: \(publicKey.verifyAsDER(signature: signature, message: diget))")  // 오타 수정
            print("키 비교 결과: \(privateKey.getPublicKeySecp256k1(compressed: false).data.hexString == publicKey.data.hexString)")
            
        }, label: {
            Text("Button")
        })
    }
}

// 나머지 함수들은 그대로 유지합니다.


/// key에 header를 떼는 함수
func removeHeadersFromKeyString(
    _ keyString: String
) -> String {
    let keyList = keyString
        .split(separator: "\n")
    return String(keyList[1])
}

func privateKeyFrom(keyString: String) -> PrivateKey? {
    // 1. header 떼기
    let keyStringWithoutHeaders: String = removeHeadersFromKeyString(keyString)
    // 2. hexString으로 변환
    guard let hexString = base64ToHexString( keyStringWithoutHeaders) else {return nil}
    
    // 3. prefix 떼기
    let privateKeyStartIndex = hexString.index(hexString.startIndex, offsetBy: 14)
    let privateKeyEndIndex = hexString.index(hexString.startIndex, offsetBy: 77)
    
    let privateKey = String(hexString[privateKeyStartIndex...privateKeyEndIndex])
    
    let data = Data(hexString: privateKey)
    guard let data else { return nil }
    return PrivateKey(data: data)
}

func publicKeyFrom(keyString: String) -> PublicKey? {
    // 1. header 떼기
    let keyStringWithoutHeaders: String = removeHeadersFromKeyString(keyString)
    // 2. hexString으로 변환
    let hexString = base64ToHexString(keyStringWithoutHeaders)
    // 3. prefix 떼기
    let publicKey = removePublicHexStringPrefix(hexString ?? "")
    
    let data = Data(hexString: publicKey)
    guard let data else { return nil }
    return PublicKey(data: data, type: .secp256k1Extended)
}


func hexStringDataFromKeyString(keyString: String) -> Data? {
    let keyStringWithoutHeaders: String = removeHeadersFromKeyString(keyString)
    let data = Data(base64Encoded: keyStringWithoutHeaders)
    return data
}

func base64EncodedString(from pemString: String) -> String {
    let lines = pemString.components(separatedBy: "\n")
    let base64Lines = lines.dropFirst().dropLast()
    return base64Lines.joined()
}

func hexString(from data: Data) -> String {
    return data.map { String(format: "%02x", $0) }.joined()
}

/// publicKey hex -> prefix 떼기
public func removePublicHexStringPrefix(_ hexString: String) -> String {
    String(hexString.replacingOccurrences(of: "3056301006072a8648ce3d020106052b8104000a034200", with: ""))
}
public func base64ToHexString(_ base64String: String) -> String? {
    guard let data = Data(base64Encoded: base64String) else {
        return nil
    }
    return data.map { String(format: "%02x", $0) }.joined()
}
