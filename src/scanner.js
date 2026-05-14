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

/**
 * Represents a security scan result for a transaction or account.
 *
 * @typedef {Object} ScanResult
 * @property {'safe' | 'warning' | 'danger'} severity - Overall risk level.
 * @property {string} summary - One-line summary of findings.
 * @property {Array<{type: string, severity: 'low' | 'medium' | 'high', message: string, detail?: string}>} findings - Individual findings.
 */

/**
 * Known high-risk address patterns (prefix-based).
 * These are placeholder patterns — real integration would use a blocklist API.
 *
 * @type {Array<{prefix: string, label: string, severity: string}>}
 */
const KNOWN_RISKY_PATTERNS = [
  // Placeholder: known scam/phishing addresses would go here
]

/**
 * ERC-20 function selectors for high-risk operations.
 *
 * @type {Object<string, string>}
 */
const RISK_SELECTORS = {
  '0x095ea7b3': 'approve',
  '0xa22cb465': 'setApprovalForAll',
  '0xf2fde38b': 'transferOwnership',
  '0x79cc6790': 'renounceOwnership',
  '0x2e1a7d4d': 'withdraw (WETH-like)'
}

export default class TransactionScanner {
  /**
   * @param {Object} [options]
   * @param {string[]} [options.knownScamAddresses] - Known scam address blocklist.
   * @param {number} [options.maxApprovalThreshold] - Max safe approval amount in wei (default: 10^18 = ~$3k ETH at $3k/ETH scale).
   */
  constructor (options = {}) {
    this._scamAddresses = new Set(options.knownScamAddresses ?? [])
    this._maxApprovalThreshold = options.maxApprovalThreshold ?? 10n ** 18n
  }

  /**
   * Scan a transaction for security risks.
   *
   * @param {Object} tx - Transaction to scan.
   * @param {string} [tx.to] - Recipient address.
   * @param {string} [tx.data] - Raw transaction calldata (hex).
   * @param {string} [tx.value] - Value in hex or decimal string.
   * @returns {ScanResult} Scan result.
   */
  scanTransaction (tx) {
    const findings = []

    // 1. Check destination address
    if (tx.to) {
      const addrCheck = this._checkAddress(tx.to)
      if (addrCheck) findings.push(addrCheck)
    }

    // 2. Decode and analyze calldata
    if (tx.data && tx.data !== '0x' && tx.data.length >= 10) {
      const selector = tx.data.slice(0, 10).toLowerCase()
      const knownOp = RISK_SELECTORS[selector]

      if (knownOp) {
        if (selector === '0x095ea7b3') {
          // ERC-20 approve — check spender and amount
          const spender = '0x' + tx.data.slice(34, 74)
          const amount = BigInt('0x' + tx.data.slice(74, 138))

          if (spender) {
            findings.push({
              type: 'approve',
              severity: amount >= this._maxApprovalThreshold ? 'high' : 'medium',
              message: `ERC-20 approval detected for spender: ${spender}`,
              detail: amount === BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
                ? 'UNLIMITED approval — spender can drain all tokens'
                : `Approval amount: ${amount.toString()}`
            })

            if (this._scamAddresses.has(spender.toLowerCase())) {
              findings.push({
                type: 'scam_spender',
                severity: 'high',
                message: `Spender address ${spender} is on known scam blocklist!`,
                detail: 'This address has been flagged as malicious.'
              })
            }
          }
        } else if (selector === '0xa22cb465') {
          findings.push({
            type: 'set_approval_for_all',
            severity: 'high',
            message: 'setApprovalForAll — operator can control ALL tokens',
            detail: 'This gives full control over all tokens in the contract.'
          })
        } else {
          findings.push({
            type: 'sensitive_operation',
            severity: 'medium',
            message: `Sensitive operation: ${knownOp}`,
            detail: 'Verify this operation was intentionally invoked.'
          })
        }
      }
    }

    // 3. Check for high value transfers
    if (tx.value && BigInt(tx.value) > 0n) {
      const val = BigInt(tx.value)
      findings.push({
        type: 'native_transfer',
        severity: val > 10n ** 20n ? 'medium' : 'low',
        message: `Native token transfer of ${val.toString()} wei`,
        detail: val > 10n ** 21n ? 'Unusually large transfer amount.' : undefined
      })
    }

    const highCount = findings.filter(f => f.severity === 'high').length
    const medCount = findings.filter(f => f.severity === 'medium').length

    /** @type {'safe' | 'warning' | 'danger'} */
    let severity = 'safe'
    if (highCount > 0) severity = 'danger'
    else if (medCount > 0) severity = 'warning'

    return {
      severity,
      summary: highCount > 0
        ? `${highCount} high-risk finding(s) detected`
        : medCount > 0
          ? `${medCount} medium-risk finding(s) detected`
          : 'No security issues detected',
      findings
    }
  }

  /**
   * Check an address against known patterns.
   *
   * @param {string} address - Ethereum-style address (0x-prefixed).
   * @returns {Object|undefined}
   */
  _checkAddress (address) {
    const lowered = address.toLowerCase()

    if (this._scamAddresses.has(lowered)) {
      return {
        type: 'scam_address',
        severity: 'high',
        message: `Address ${address} is on known scam blocklist`,
        detail: 'Transactions to this address are blocked.'
      }
    }

    return undefined
  }

  /**
   * Register additional scam addresses.
   *
   * @param {string[]} addresses - Addresses to add to the blocklist.
   */
  addScamAddresses (addresses) {
    for (const addr of addresses) {
      this._scamAddresses.add(addr.toLowerCase())
    }
  }
}
