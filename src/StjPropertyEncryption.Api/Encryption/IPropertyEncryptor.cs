namespace StjPropertyEncryption.Api.Encryption;

public interface IPropertyEncryptor
{
    string Encrypt(string plaintext);

    string Decrypt(string payload);
}
