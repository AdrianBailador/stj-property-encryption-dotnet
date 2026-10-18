# STJ Property Encryption

Companion repo for [Your Database Column Is Encrypted. Your JSON Response Isn't.](https://adrianbailador.github.io/blog/74-property-encryption-system-text-json) — a minimal, runnable demo of transparent property-level encryption for `System.Text.Json`, using a `JsonTypeInfo` modifier instead of a converter per type.

## The problem, in one pair of endpoints

`GET /users/{id}` serializes a `User` with the default resolver — `Email`, `Ssn`, and the nested `Address.PostalCode` go out exactly as they're held in memory.

`GET /secure/users/{id}` serializes the same `User`, same model, with a resolver built from `new DefaultJsonTypeInfoResolver().WithAddedModifier(...)`. Every property marked `[Encrypted]` — anywhere in the object graph — is encrypted on the way out and decrypted on the way in. Nothing in `User` or `Address` knows this is happening.

## How it works

- **`Encryption/EncryptedAttribute.cs`** — a plain marker attribute on a property.
- **`Encryption/AesGcmPropertyEncryptor.cs`** — AES-GCM with a random 12-byte nonce per call, so encrypting the same value twice never produces the same ciphertext.
- **`Serialization/EncryptionTypeInfoModifier.cs`** — the actual mechanism: skips non-`Object` contracts, walks `JsonTypeInfo.Properties`, finds every property with `[Encrypted]` via `AttributeProvider`, and rewrites its `Get`/`Set` delegates to encrypt/decrypt through `IPropertyEncryptor`. A property marked `[Encrypted]` on a non-`string` type throws `InvalidOperationException` at first use. A value that isn't valid ciphertext for the configured key — wrong format, too short, wrong key, tampered data — throws a `JsonException` naming the exact type and property, instead of a raw crypto exception three frames down; anything else (a bug in `IPropertyEncryptor` itself) still propagates unchanged.

## Key management (demo scope)

The AES-256 key in `appsettings.json` is here for one reason: so you can run this repo without standing up a secret store first. It is not how a real deployment should hold a key. Two things this demo deliberately leaves out, because they're deployment-specific, not `System.Text.Json`-specific:

- **Where the key lives.** A real deployment reads it from a key vault or secret manager at startup, never from a file that gets checked into source control.
- **What happens when it rotates.** This demo has exactly one key, ever. A real system needs to know which key encrypted which value — typically a short key identifier stored alongside the ciphertext — so old data stays decryptable after the active key changes. Losing the key entirely means the ciphertext it produced is permanently unreadable; there's no recovery path around that by design.

## Running it

```bash
dotnet test                                      # 11 tests: leak check, round-trip, nested graph + collections,
                                                  # fail-fast guard, and five decryption failure modes
dotnet run --project src/StjPropertyEncryption.Api   # API on the port printed to the console
```

```bash
# Before — plaintext on the wire
curl http://localhost:<port>/users/42

# After — same model, same data, Email/Ssn/PostalCode are ciphertext
curl http://localhost:<port>/secure/users/42
```

## Project layout

```
src/StjPropertyEncryption.Api/
  Models/User.cs, Address.cs                     [Encrypted] on the sensitive properties
  Encryption/EncryptedAttribute.cs
  Encryption/IPropertyEncryptor.cs
  Encryption/AesGcmPropertyEncryptor.cs           AES-GCM, random nonce per call
  Serialization/EncryptionTypeInfoModifier.cs     the JsonTypeInfo modifier itself
  Program.cs                                      /users (before) vs /secure/users (after)
tests/StjPropertyEncryption.Tests/
  EncryptionModifierTests.cs                      11 tests: the leak, the fix, nested/collection graphs,
                                                   the misconfiguration guard, and the failure modes —
                                                   plaintext input, wrong-key ciphertext, a too-short
                                                   payload, and a property with no setter
```

## License

MIT — use this however's useful.
