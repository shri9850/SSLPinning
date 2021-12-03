//
//  ServiceManager.swift
//  SSLPinning
//
//  Created by shree on 03/12/21.
//

import Foundation
import Security
import CommonCrypto
class ServiceManager: NSObject {
    private var isCertificatePinning: Bool = false
    static let publicKeyHash = "xucKip6j7mWOyo3bckw4d9SBBL3EsFqiBM2nGxM5N+E="
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
    func callAPI(withURL url:URL, isCertificatePinning: Bool, completion: @escaping(String)->Void){
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        self.isCertificatePinning = isCertificatePinning
        var responsesMessage = ""
        let task = session.dataTask(with: url){(data,responses,error) in
            if error != nil{
                print(error?.localizedDescription as Any)
                responsesMessage = "Pinning failed"
            }else if data != nil {
                let str = String(decoding: data!, as: UTF8.self)
                print("Received Data \(str)")
                if isCertificatePinning{
                    responsesMessage = "Certificate Pinning is successfully"
                }else{
                     responsesMessage = "Public key Pinning is successfully"
                }
            }
            DispatchQueue.main.async {
                completion(responsesMessage)
            }
        }
        task.resume()
        
    }
}
extension ServiceManager: URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        if self.isCertificatePinning {
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            //Local and Remote certificate Data
            let remoteCertificateData:NSData =  SecCertificateCopyData(certificate!)
            //let LocalCertificate = Bundle.main.path(forResource: "github.com", ofType: "cer")
            let pathToCertificate = Bundle.main.path(forResource: "google", ofType: "cer")
            let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,credential)
            }
            else {
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }else {
            if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                // Server public key
                let serverPublicKey = SecCertificateCopyKey(serverCertificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                let data:Data = serverPublicKeyData as Data
                // Server Hash key
                let serverHashKey = sha256(data: data)
                print("Serverhash Key \(serverHashKey)")
                // Local Hash Key
                let publickKeyLocal = type(of: self).publicKeyHash
                print("publickKeyLocal Key \(publickKeyLocal)")
                if (serverHashKey == publickKeyLocal) {
                    // Success! This is our server
                    print("Public key pinning is successfully completed")
                    completionHandler(.useCredential, URLCredential(trust:serverTrust))
                    return
                }
            }
        }
    }
}
