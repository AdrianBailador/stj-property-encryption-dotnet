using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using StjPropertyEncryption.Api.Encryption;

namespace StjPropertyEncryption.Api.Serialization;

public static class EncryptionTypeInfoModifier
{
    public static Action<JsonTypeInfo> Create(IPropertyEncryptor encryptor)
    {
        return typeInfo =>
        {
            // Get/Set rewriting only makes sense for object contracts — a List<T> or
            // Dictionary<TKey,TValue> contract has no comparable per-property hook.
            if (typeInfo.Kind != JsonTypeInfoKind.Object)
            {
                return;
            }

            foreach (var property in typeInfo.Properties)
            {
                var isEncrypted = property.AttributeProvider
                    ?.GetCustomAttributes(typeof(EncryptedAttribute), inherit: false)
                    .Length > 0;

                if (!isEncrypted)
                {
                    continue;
                }

                if (property.PropertyType != typeof(string))
                {
                    throw new InvalidOperationException(
                        $"[Encrypted] on '{typeInfo.Type.Name}.{property.Name}' requires a string property, " +
                        $"but '{property.Name}' is '{property.PropertyType.Name}'.");
                }

                var originalGet = property.Get;
                var originalSet = property.Set;

                if (originalGet is not null)
                {
                    property.Get = instance =>
                    {
                        var plaintext = (string?)originalGet(instance);
                        return plaintext is null ? null : encryptor.Encrypt(plaintext);
                    };
                }

                if (originalSet is not null)
                {
                    var propertyName = property.Name;
                    var declaringTypeName = typeInfo.Type.Name;

                    property.Set = (instance, value) =>
                    {
                        var ciphertext = (string?)value;
                        if (ciphertext is null)
                        {
                            originalSet(instance, null);
                            return;
                        }

                        string plaintext;
                        try
                        {
                            plaintext = encryptor.Decrypt(ciphertext);
                        }
                        catch (Exception ex)
                        {
                            // Covers invalid base64, a too-short payload, and an AES-GCM
                            // authentication tag mismatch (wrong key or tampered data) alike —
                            // to the caller, all three mean the same thing: this wasn't
                            // ciphertext this encryptor produced.
                            throw new JsonException(
                                $"'{declaringTypeName}.{propertyName}' is marked [Encrypted], but the incoming " +
                                "value isn't valid ciphertext for the configured key. If this endpoint is meant " +
                                "to accept plaintext input, don't bind its request body with the encrypting " +
                                "resolver — only use it for values round-tripped from this API's own responses.",
                                ex);
                        }

                        originalSet(instance, plaintext);
                    };
                }
            }
        };
    }
}
