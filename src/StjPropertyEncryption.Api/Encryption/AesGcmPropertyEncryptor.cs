using System.Security.Cryptography;
using System.Text;

namespace StjPropertyEncryption.Api.Encryption;

public sealed class AesGcmPropertyEncryptor : IPropertyEncryptor
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly byte[] _key;

    public AesGcmPropertyEncryptor(IConfiguration configuration)
    {
        var base64Key = configuration["Encryption:Key"]
            ?? throw new InvalidOperationException("Missing 'Encryption:Key' configuration value.");
        _key = Convert.FromBase64String(base64Key);
    }

    public string Encrypt(string plaintext)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using (var aesGcm = new AesGcm(_key, TagSize))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        var payload = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, payload, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, payload, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, payload, NonceSize + TagSize, ciphertext.Length);

        return Convert.ToBase64String(payload);
    }

    public string Decrypt(string payload)
    {
        var payloadBytes = Convert.FromBase64String(payload);

        var nonce = payloadBytes[..NonceSize];
        var tag = payloadBytes[NonceSize..(NonceSize + TagSize)];
        var ciphertext = payloadBytes[(NonceSize + TagSize)..];
        var plaintextBytes = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(_key, TagSize))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes);
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }
}
