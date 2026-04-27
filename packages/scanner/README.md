# @sonofgotham/quell-scanner

Offline secret-detection engine. The core scanner behind the [Quell VSCode extension](https://marketplace.visualstudio.com/items?itemName=Sonofg0tham.quell).

- 75+ regex patterns covering AWS, Google, Azure, OpenAI, Anthropic, Stripe, GitHub, Slack, databases, private keys, and more
- Shannon entropy fallback for high-randomness tokens that don't match a named pattern
- Zero runtime dependencies
- Works in Node 18+. No VSCode or browser APIs

## Install

```bash
npm install @sonofgotham/quell-scanner
```

## Usage

```ts
import { SecretScanner, DEFAULT_CONFIG } from '@sonofgotham/quell-scanner';

const { redactedText, secrets, detectedTypes } = SecretScanner.redact(
  'Token: ghp_ABCDEFabcdef1234567890abcdef123456',
  DEFAULT_CONFIG
);

console.log(redactedText);
// "Token: {{SECRET_a1b2c3d4e5f6a1b2}}"

console.log(detectedTypes);
// Set { "GitHub Personal Access Token" }

console.log(secrets);
// Map { "{{SECRET_a1b2c3d4e5f6a1b2}}" => "ghp_ABCDEFabcdef1234567890abcdef123456" }
```

> **Note:** Placeholders use 16 hex characters (`{{SECRET_[a-f0-9]{16}}}`), giving 2^64 possible values for collision resistance across large vaults.

## Configuration

```ts
import { ScannerConfig, SecretScanner } from '@sonofgotham/quell-scanner';

const config: ScannerConfig = {
  enableEntropy: true,
  entropyThreshold: 4.5,
  minimumTokenLength: 20,
  customPatterns: [
    { name: 'Internal API Key', regex: 'int_[a-f0-9]{32}' },
  ],
  whitelistPatterns: [],
  redactTestKeys: false,
};

SecretScanner.redact(text, config);
```

### `redactTestKeys`

By default (`false`), officially-published test/demo credentials (e.g. `AKIAIOSFODNN7EXAMPLE`, `sk_test_...`) are left alone. These appear in READMEs, tutorials, and documentation and are intentionally safe.

Set to `true` to treat them like any other secret:

```ts
SecretScanner.redact(text, { ...DEFAULT_CONFIG, redactTestKeys: true });
```

## Status

Currently versioned as 0.1.0 and not yet published to npm. Distributed as source alongside the Quell VSCode extension. Standalone npm publish is planned.

## License

MIT
