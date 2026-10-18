using StjPropertyEncryption.Api.Encryption;

namespace StjPropertyEncryption.Api.Models;

public sealed class User
{
    public required int Id { get; set; }

    public required string Name { get; set; }

    [Encrypted]
    public required string Email { get; set; }

    [Encrypted]
    public required string Ssn { get; set; }

    public required Address Address { get; set; }
}
