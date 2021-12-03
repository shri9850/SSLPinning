//
//  ViewController.swift
//  SSLPinning
//
//  Created by shree on 03/12/21.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        self.callApi()
    }
    private func callApi(){
        guard let url = URL(string: "https://www.google.co.uk") else { return }
        ServiceManager().callAPI(withURL: url, isCertificatePinning: false) { (responsesMessage) in
            let alert = UIAlertController(title: "SSL Pinning", message: responsesMessage, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "Ok", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }

}

