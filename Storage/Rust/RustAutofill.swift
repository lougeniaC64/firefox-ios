// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

import Foundation
import Shared
@_exported import MozillaAppServices
import Common

typealias AutofillStore = Store

public extension AutofillApiError {
    var descriptionValue: String {
        switch self {
        case .SqlError: return "SqlError"
        case .CryptoError: return "CryptoError"
        case .NoSuchRecord: return "NoSuchRecord"
        case .UnexpectedAutofillApiError: return "UnexpectedAutofillApiError"
        case .InterruptedError: return "InterruptedError"
        }
    }
}

public enum AutofillEncryptionKeyError: Error {
    case illegalState
    case noKeyCreated
}

// Note: This was created in lieu of a view model
public struct UnencryptedCreditCardFields {
    public var ccName: String = ""
    public var ccNumber: String = ""
    public var ccNumberLast4: String = ""
    public var ccExpMonth: Int64 = 0
    public var ccExpYear: Int64 = 0
    public var ccType: String = ""

    public init() { }

    public init(ccName: String,
                ccNumber: String,
                ccNumberLast4: String,
                ccExpMonth: Int64,
                ccExpYear: Int64,
                ccType: String) {
        self.ccName = ccName
        self.ccNumber = ccNumber
        self.ccNumberLast4 = ccNumberLast4
        self.ccExpMonth = ccExpMonth
        self.ccExpYear = ccExpYear
        self.ccType = ccType
    }

    func toUpdatableCreditCardFields() -> UpdatableCreditCardFields {
        let rustKeys = RustAutofillEncryptionKeys()
        let ccNumberEnc = rustKeys.encryptCreditCardNum(creditCardNum: self.ccNumber)
        return UpdatableCreditCardFields(ccName: self.ccName,
                                         ccNumberEnc: ccNumberEnc ?? "",
                                         ccNumberLast4: self.ccNumberLast4,
                                         ccExpMonth: self.ccExpMonth,
                                         ccExpYear: self.ccExpYear,
                                         ccType: self.ccType)
    }

    public func convertToTempCreditCard() -> CreditCard {
        let convertedCreditCard = CreditCard(guid: "",
                                             ccName: self.ccName,
                                             ccNumberEnc: "",
                                             ccNumberLast4: self.ccNumberLast4,
                                             ccExpMonth: self.ccExpMonth,
                                             ccExpYear: self.ccExpYear,
                                             ccType: self.ccType,
                                             timeCreated: Int64(Date().timeIntervalSince1970),
                                             timeLastUsed: nil,
                                             timeLastModified: Int64(Date().timeIntervalSince1970),
                                             timesUsed: 0)
        return convertedCreditCard
    }

    public func isEqualToCreditCard(creditCard: CreditCard) -> Bool {
        return creditCard.ccExpMonth == ccExpMonth &&
        creditCard.ccExpYear == ccExpYear &&
        creditCard.ccName == ccName &&
        creditCard.ccNumberLast4 == ccNumberLast4
    }
}

public class RustAutofillEncryptionKeys {
    public let ccKeychainKey = "appservices.key.creditcard.perfield"

    let keychain = MZKeychainWrapper.sharedClientAppContainerKeychain
    let ccCanaryPhraseKey = "creditCardCanaryPhrase"
    let canaryPhrase = "a string for checking validity of the key"

    private let logger: Logger

    public init(logger: Logger = DefaultLogger.shared) {
        self.logger = logger
    }

    fileprivate func createAndStoreKey() throws -> String {
        do {
            let secret = try createAutofillKey()
            let canary = try self.createCanary(text: canaryPhrase, key: secret)

            keychain.set(secret,
                         forKey: ccKeychainKey,
                         withAccessibility: MZKeychainItemAccessibility.afterFirstUnlock)
            keychain.set(canary,
                         forKey: ccCanaryPhraseKey,
                         withAccessibility: MZKeychainItemAccessibility.afterFirstUnlock)

            return secret
        } catch let err as NSError {
            if let autofillStoreError = err as? AutofillApiError {
                logAutofillStoreError(err: autofillStoreError,
                                      errorDomain: err.domain,
                                      errorMessage: "Error while creating and storing credit card key")

                throw AutofillEncryptionKeyError.noKeyCreated
            } else {
                logger.log("Unknown error while creating and storing credit card key",
                           level: .warning,
                           category: .storage,
                           description: err.localizedDescription)

                throw AutofillEncryptionKeyError.noKeyCreated
            }
        }
    }

    func decryptCreditCardNum(encryptedCCNum: String) -> String? {
        guard let key = self.keychain.string(forKey: self.ccKeychainKey) else {
            return nil
        }

        do {
            return try decryptString(key: key, ciphertext: encryptedCCNum)
        } catch let err as NSError {
            if let autofillStoreError = err as? AutofillApiError {
                logAutofillStoreError(err: autofillStoreError,
                                      errorDomain: err.domain,
                                      errorMessage: "Error while decrypting credit card")
            } else {
                logger.log("Unknown error while decrypting credit card",
                           level: .warning,
                           category: .storage,
                           description: err.localizedDescription)
            }
            return nil
        }
    }

    fileprivate func checkCanary(canary: String,
                                 text: String,
                                 key: String) throws -> Bool {
        return try decryptString(key: key, ciphertext: canary) == text
    }

    func encryptCreditCardNum(creditCardNum: String) -> String? {
        guard let key = self.keychain.string(forKey: self.ccKeychainKey) else {
            return nil
        }

        do {
            return try encryptString(key: key, cleartext: creditCardNum)
        } catch let err as NSError {
            if let autofillStoreError = err as? AutofillApiError {
                logAutofillStoreError(err: autofillStoreError,
                                      errorDomain: err.domain,
                                      errorMessage: "Error while encrypting credit card")
            } else {
                logger.log("Unknown error while encrypting credit card",
                           level: .warning,
                           category: .storage,
                           description: err.localizedDescription)
            }
        }
        return nil
    }

    fileprivate func createCanary(text: String,
                                  key: String) throws -> String {
        return try encryptString(key: key, cleartext: text)
    }

    private func logAutofillStoreError(err: AutofillApiError,
                                       errorDomain: String,
                                       errorMessage: String) {
        var message: String {
            switch err {
            case .SqlError(let message),
                    .CryptoError(let message),
                    .NoSuchRecord(let message),
                    .UnexpectedAutofillApiError(let message):
                return message
            case .InterruptedError:
                return "Interrupted Error"
            }
        }

        logger.log(errorMessage,
                   level: .warning,
                   category: .storage,
                   description: "\(errorDomain) - \(err.descriptionValue): \(message)")
    }
}

public class RustAutofill {
    let databasePath: String

    let queue: DispatchQueue
    var storage: AutofillStore?

    private(set) var isOpen = false

    private var didAttemptToMoveToBackup = false

    private let logger: Logger

    public init(databasePath: String,
                logger: Logger = DefaultLogger.shared) {
        self.databasePath = databasePath

        queue = DispatchQueue(label: "RustAutofill queue: \(databasePath)",
                              attributes: [])
        self.logger = logger
    }

    private func open() -> NSError? {
        do {
            getStoredKey { _ in }
            storage = try AutofillStore(dbpath: databasePath)
            isOpen = true
            return nil
        } catch let err as NSError {
            if let autofillStoreError = err as? AutofillApiError {
                // This is an unrecoverable
                // state unless we can move the existing file to a backup
                // location and start over.
                logger.log("Rust Autofill store error when opening database",
                           level: .warning,
                           category: .storage,
                           description: autofillStoreError.localizedDescription)
            } else {
                logger.log("Unknown error when opening Rust Autofill database",
                           level: .warning,
                           category: .storage,
                           description: err.localizedDescription)
            }

            if !didAttemptToMoveToBackup {
                RustShared.moveDatabaseFileToBackupLocation(
                    databasePath: self.databasePath)
                didAttemptToMoveToBackup = true
                return open()
            }

            return err
        }
    }

    private func close() -> NSError? {
        storage = nil
        isOpen = false
        return nil
    }

    public func reopenIfClosed() -> NSError? {
        var error: NSError?

        queue.sync {
            guard !isOpen else { return }

            error = open()
        }

        return error
    }

    public func forceClose() -> NSError? {
        var error: NSError?

        queue.sync {
            guard isOpen else { return }

            error = close()
        }

        return error
    }

    public func addCreditCard(creditCard: UnencryptedCreditCardFields, completion: @escaping (CreditCard?, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(nil, error)
                return
            }

            do {
                let id = try self.storage?.addCreditCard(cc: creditCard.toUpdatableCreditCardFields())
                completion(id!, nil)
            } catch let err as NSError {
                completion(nil, err)
            }
        }
    }

    public func getCreditCard(id: String, completion: @escaping (CreditCard?, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(nil, error)
                return
            }

            do {
                let record = try self.storage?.getCreditCard(guid: id)
                completion(record, nil)
            } catch let err as NSError {
                completion(nil, err)
            }
        }
    }

    public func decryptCreditCardNumber(encryptedCCNum: String?) -> String? {
        guard let encryptedCCNum = encryptedCCNum, !encryptedCCNum.isEmpty else {
            return nil
        }
        let keys = RustAutofillEncryptionKeys()
        let num = keys.decryptCreditCardNum(encryptedCCNum: encryptedCCNum)
        return num
    }

    public func listCreditCards(completion: @escaping ([CreditCard]?, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(nil, error)
                return
            }

            do {
                let records = try self.storage?.getAllCreditCards()
                completion(records, nil)
            } catch let err as NSError {
                completion(nil, err)
            }
        }
    }

    public func listCreditCards(completion: @escaping (Result<[CreditCard]?, Error>) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(.failure(error))
                return
            }

            do {
                let records = try self.storage?.getAllCreditCards()
                completion(.success(records))
            } catch let err as NSError {
                completion(.failure(err))
            }
        }
    }

    public func hasSyncedCreditCards(completion: @escaping (Result<Bool, Error>) -> Void) {
        listCreditCards { result in
            switch result {
            case .success(let creditCards):
                completion(.success((creditCards?.count ?? 0) > 0))
            case .failure(let err):
                completion(.failure(err))
            }
        }
    }

    public func checkForCreditCardExistance(cardNumber: String, completion: @escaping (CreditCard?, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(nil, error)
                return
            }

            do {
                guard let records = try self.storage?.getAllCreditCards(),
                      let foundCard = records.first(where: { $0.ccNumberLast4 == cardNumber })
                else {
                    completion(nil, nil)
                    return
                }
                completion(foundCard, nil)
            } catch let err as NSError {
                completion(nil, err)
            }
        }
    }

    public func updateCreditCard(id: String, creditCard: UnencryptedCreditCardFields, completion: @escaping (Bool, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(false, error)
                return
            }

            do {
                try self.storage?.updateCreditCard(
                    guid: id,
                    cc: creditCard.toUpdatableCreditCardFields())
                completion(true, nil)
            } catch let err as NSError {
                completion(false, err)
            }
        }
    }

    public func deleteCreditCard(id: String, completion: @escaping (Bool, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(false, error)
                return
            }

            do {
                let existed = try self.storage?.deleteCreditCard(guid: id)
                completion(existed!, nil)
            } catch let err as NSError {
                completion(false, err)
            }
        }
    }

    public func use(creditCard: CreditCard, completion: @escaping (Bool, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(false, error)
                return
            }

            do {
                try self.storage?.touchCreditCard(guid: creditCard.guid)
                completion(true, nil)
            } catch let err as NSError {
                completion(false, err)
            }
        }
    }

    //TODO: Result<Void, AuthenticationError>
    public func scrubCreditCardNums(completion: @escaping (Bool, Error?) -> Void) {
        queue.async {
            guard self.isOpen else {
                let error = AutofillApiError.UnexpectedAutofillApiError(
                    reason: "Database is closed")
                completion(false, error)
                return
            }

            do {
                try self.storage?.scrubEncryptedData()
                completion(true, nil)
            } catch let err as NSError {
                completion(false, err)
            }
        }
    }

    public func registerWithSyncManager() {
        queue.async { [unowned self] in
            self.storage?.registerWithSyncManager()
        }
    }

    private func resetCreditCardsAndKey(rustKeys: RustAutofillEncryptionKeys,
                                        completion: @escaping (Result<String, NSError>) -> Void) {
        self.scrubCreditCardNums(completion: { _, err in
            if err != nil {
                completion(.failure(err! as NSError))
            } else {
                do {
                    let key = try rustKeys.createAndStoreKey()
                    completion(.success(key))
                } catch let error as NSError {
                    self.logger.log("Error creating new Autofill key: \(error)",
                                    level: .warning,
                                    category: .storage,
                                    description: error.localizedDescription)
                    completion(.failure(error))
                }
            }
        })
    }

    public func getStoredKey(completion: @escaping (Result<String, NSError>) -> Void) {
        let rustKeys = RustAutofillEncryptionKeys()
        let key = rustKeys.keychain.string(forKey: rustKeys.ccKeychainKey)
        let encryptedCanaryPhrase = rustKeys.keychain.string(
            forKey: rustKeys.ccCanaryPhraseKey)

        switch(key, encryptedCanaryPhrase) {
        case (.some(key), .some(encryptedCanaryPhrase)):
            // We expected the key to be present, and it is.
            do {
                let canaryIsValid = try rustKeys.checkCanary(
                    canary: encryptedCanaryPhrase!,
                    text: rustKeys.canaryPhrase,
                    key: key!)

                if canaryIsValid {
                    completion(.success(key!))
                } else {
                    logger.log("Autofill key was corrupted, new one generated",
                               level: .warning,
                               category: .storage)
                    self.resetCreditCardsAndKey(rustKeys: rustKeys, completion: completion)
                }
            } catch let error as NSError {
                logger.log("Error validating Autofill key",
                           level: .warning,
                           category: .storage,
                           description: error.localizedDescription)
                completion(.failure(error))
            }
        case (.some(key), .none):
            // The key is present, but we didn't expect it to be there.
            logger.log("Autofill key lost due to storage malfunction, new one generated",
                       level: .warning,
                       category: .storage)
            self.resetCreditCardsAndKey(rustKeys: rustKeys, completion: completion)
        case (.none, .some(encryptedCanaryPhrase)):
            // We expected the key to be present, but it's gone missing on us.
            logger.log("Autofill key lost, new one generated",
                       level: .warning,
                       category: .storage)
            self.resetCreditCardsAndKey(rustKeys: rustKeys, completion: completion)
        case (.none, .none):
            // We didn't expect the key to be present, which either means this is a first-time
            // call or the key data has been cleared from the keychain.

            self.hasSyncedCreditCards { result in
                switch result {
                case .success(let hasCreditCards):
                    if hasCreditCards {
                        // Since the key data isn't present and we have credit card records in
                        // the database, we both clear the databbase and the reset the key.
                        self.resetCreditCardsAndKey(rustKeys: rustKeys, completion: completion)
                    } else {
                        do {
                            let key = try rustKeys.createAndStoreKey()
                            completion(.success(key))
                        } catch let error as NSError {
                            completion(.failure(error))
                        }
                    }
                case .failure(let err):
                    completion(.failure(err as NSError))
                }
            }
        default:
            // If none of the above cases apply, we're in a state that shouldn't be possible
            // but is disallowed nonetheless
            completion(.failure(AutofillEncryptionKeyError.illegalState as NSError))
        }
    }
}
