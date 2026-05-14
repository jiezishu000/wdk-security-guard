# WDK Security Guard

> Transaction security analysis middleware for [Tether WDK](https://wdk.tether.io).

Scans transactions for common security risks **before** signing:
- Unlimited ERC-20 approvals (`type(uint256).max`)
- `setApprovalForAll` calls
- Sensitive operations (ownership transfers, renounce)
- Known scam/blocklisted destination addresses
- Unusually large transfers

## Installation

```bash
npm install github:jiezishu000/wdk-security-guard

# (once published to npm: `npm install @jiezishu000/wdk-security-guard`)
```

## Quick Start

```javascript
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import securityMiddleware from '@jiezishu000/wdk-security-guard/middleware'

const wdk = new WDK(seedPhrase)
  .registerWallet('ethereum', WalletManagerEvm, { rpcUrl })
  .registerMiddleware('ethereum', securityMiddleware())

const account = await wdk.getAccount('ethereum', 0)

const result = account.security.scan({
  to: '0x...',
  data: '0x095ea7b3...'  // approve() call
})

console.log(result.severity)   // 'warning' | 'danger' | 'safe'
console.log(result.summary)    // '1 high-risk finding detected'
console.log(result.findings)   // [{ type, severity, message, detail }]
```

## API

### `securityMiddleware(options?)`

Factory function returning a WDK middleware.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `knownScamAddresses` | `string[]` | `[]` | Address blocklist |
| `maxApprovalThreshold` | `bigint` | `10^18` | Max safe approval wei |

### `TransactionScanner`

Direct-use scanner (without middleware).

```javascript
import { TransactionScanner } from '@jiezishu000/wdk-security-guard'
const scanner = new TransactionScanner()
const result = scanner.scanTransaction({ to, data, value })
```

## License

Apache-2.0

---

**Donations:** `0x1b6C028199952eE1a8079dB02acfFCCfC881f76d` (Polygon USDT)
