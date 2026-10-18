using System.Text.Json.Serialization.Metadata;
using StjPropertyEncryption.Api.Encryption;

namespace StjPropertyEncryption.Api.Serialization;

public static class EncryptionTypeInfoModifier
{
    public static Action<JsonTypeInfo> Create(IPropertyEncryptor encryptor)
    {
        return typeInfo =>
        {
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
                    property.Set = (instance, value) =>
                    {
                        var ciphertext = (string?)value;
                        originalSet(instance, ciphertext is null ? null : encryptor.Decrypt(ciphertext));
                    };
                }
            }
        };
    }
}
