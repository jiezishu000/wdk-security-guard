// Copyright 2026 jiezishu000
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

'use strict'

import TransactionScanner from './scanner.js'

/**
 * WDK middleware that attaches a security scanner to derived accounts.
 *
 * After registration via `wdk.registerMiddleware(blockchain, securityMiddleware)`,
 * every derived account will have a `security` property with a `TransactionScanner`
 * instance and the last scan results.
 *
 * @example
 * ```javascript
 * import WDK from '@tetherto/wdk'
 * import securityMiddleware from '@jiezishu000/wdk-security-guard/middleware'
 *
 * const wdk = new WDK(seedPhrase)
 *   .registerWallet('ethereum', WalletManagerEvm, { rpcUrl })
 *   .registerMiddleware('ethereum', securityMiddleware)
 *
 * const account = await wdk.getAccount('ethereum', 0)
 * // account.security.scanner — TransactionScanner instance
 * // account.security.scanTransaction(tx) — scan a transaction
 * ```
 */

/**
 * Creates a WDK middleware that attaches a TransactionScanner to each account.
 *
 * @param {Object} [options] - Options passed to TransactionScanner constructor.
 * @param {string[]} [options.knownScamAddresses] - Known scam address blocklist.
 * @returns {import('@tetherto/wdk').MiddlewareFunction} WDK middleware function.
 */
export default function securityMiddleware (options = {}) {
  const scanner = new TransactionScanner(options)

  /**
   * @param {import('@tetherto/wdk').IWalletAccount} account
   */
  return async (account) => {
    const address = await account.getAddress()

    /** @type {{ scanner: TransactionScanner, lastScan: import('./scanner.js').ScanResult | null, address: string }} */
    const security = {
      scanner,
      lastScan: null,
      address
    }

    security.scan = (tx) => {
      const result = scanner.scanTransaction(tx)
      security.lastScan = result
      return result
    }

    account.security = security
  }
}

/**
 * Pre-configured middleware with default scam address blocklist.
 *
 * @type {import('@tetherto/wdk').MiddlewareFunction}
 */
export const defaultSecurity = async (account) => {
  const middleware = securityMiddleware()
  await middleware(account)
}
