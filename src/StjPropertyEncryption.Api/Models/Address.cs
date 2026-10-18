using StjPropertyEncryption.Api.Encryption;

namespace StjPropertyEncryption.Api.Models;

public sealed class Address
{
    public required string Street { get; set; }

    public required string City { get; set; }

    [Encrypted]
    public required string PostalCode { get; set; }
}
