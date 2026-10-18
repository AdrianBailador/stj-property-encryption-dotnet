using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Extensions.Configuration;
using StjPropertyEncryption.Api.Encryption;
using StjPropertyEncryption.Api.Models;
using StjPropertyEncryption.Api.Serialization;

namespace StjPropertyEncryption.Tests;

public class EncryptionModifierTests
{
    private static readonly IPropertyEncryptor Encryptor = CreateEncryptor();

    private static readonly JsonSerializerOptions PlainOptions = new(JsonSerializerDefaults.Web);

    private static readonly JsonSerializerOptions EncryptedOptions = new(JsonSerializerDefaults.Web)
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver()
            .WithAddedModifier(EncryptionTypeInfoModifier.Create(Encryptor))
    };

    [Fact]
    public void Plain_options_leak_sensitive_fields_as_plaintext()
    {
        var json = JsonSerializer.Serialize(CreateUser(), PlainOptions);

        Assert.Contains("jane.doe@example.com", json);
        Assert.Contains("078-05-1120", json);
        Assert.Contains("D02 AF30", json);
    }

    [Fact]
    public void Encrypted_options_never_put_plaintext_sensitive_values_on_the_wire()
    {
        var json = JsonSerializer.Serialize(CreateUser(), EncryptedOptions);

        Assert.DoesNotContain("jane.doe@example.com", json);
        Assert.DoesNotContain("078-05-1120", json);
        Assert.DoesNotContain("D02 AF30", json);
    }

    [Fact]
    public void Encrypted_options_leave_non_encrypted_fields_as_plaintext()
    {
        var json = JsonSerializer.Serialize(CreateUser(), EncryptedOptions);

        Assert.Contains("Jane Doe", json);
        Assert.Contains("1 Market St", json);
        Assert.Contains("Dublin", json);
    }

    [Fact]
    public void Encrypted_options_round_trip_to_the_original_plaintext()
    {
        var original = CreateUser();

        var json = JsonSerializer.Serialize(original, EncryptedOptions);
        var roundTripped = JsonSerializer.Deserialize<User>(json, EncryptedOptions);

        Assert.NotNull(roundTripped);
        Assert.Equal(original.Email, roundTripped!.Email);
        Assert.Equal(original.Ssn, roundTripped.Ssn);
        Assert.Equal(original.Address.PostalCode, roundTripped.Address.PostalCode);
        Assert.Equal(original.Name, roundTripped.Name);
    }

    [Fact]
    public void Ciphertext_differs_between_calls_for_the_same_plaintext()
    {
        var first = Encryptor.Encrypt("same-value");
        var second = Encryptor.Encrypt("same-value");

        Assert.NotEqual(first, second);
        Assert.Equal("same-value", Encryptor.Decrypt(first));
        Assert.Equal("same-value", Encryptor.Decrypt(second));
    }

    [Fact]
    public void Applying_Encrypted_to_a_non_string_property_fails_fast()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                .WithAddedModifier(EncryptionTypeInfoModifier.Create(Encryptor))
        };

        var ex = Assert.Throws<InvalidOperationException>(
            () => JsonSerializer.Serialize(new Misconfigured { Age = 30 }, options));

        Assert.Contains("requires a string property", ex.Message);
    }

    [Fact]
    public void Encrypted_options_round_trip_a_collection_of_encrypted_items()
    {
        var order = new Order
        {
            Id = 7,
            Shipments =
            [
                new Shipment { TrackingCode = "TRK-1", RecipientEmail = "a@example.com" },
                new Shipment { TrackingCode = "TRK-2", RecipientEmail = "b@example.com" },
            ],
        };

        var json = JsonSerializer.Serialize(order, EncryptedOptions);

        Assert.Contains("TRK-1", json);
        Assert.DoesNotContain("a@example.com", json);
        Assert.DoesNotContain("b@example.com", json);

        var roundTripped = JsonSerializer.Deserialize<Order>(json, EncryptedOptions);

        Assert.NotNull(roundTripped);
        Assert.Equal(2, roundTripped!.Shipments.Count);
        Assert.Equal("a@example.com", roundTripped.Shipments[0].RecipientEmail);
        Assert.Equal("b@example.com", roundTripped.Shipments[1].RecipientEmail);
    }

    [Fact]
    public void Deserializing_plaintext_input_as_an_encrypted_property_fails_clearly()
    {
        const string requestBody = """
            {"id":42,"name":"Jane Doe","email":"not-actually-ciphertext","ssn":"078-05-1120",
            "address":{"street":"1 Market St","city":"Dublin","postalCode":"D02 AF30"}}
            """;

        var ex = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<User>(requestBody, EncryptedOptions));

        Assert.Contains("isn't valid ciphertext", ex.Message);
    }

    [Fact]
    public void Ciphertext_decrypted_with_the_wrong_key_fails_clearly_instead_of_returning_garbage()
    {
        var wrongKeyEncryptor = CreateEncryptor(key: "Zm9vYmFyYmF6cXV1eGNvcmdlZ3JhdWx0Z2FyYnk=");
        var wrongKeyOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            TypeInfoResolver = new DefaultJsonTypeInfoResolver()
                .WithAddedModifier(EncryptionTypeInfoModifier.Create(wrongKeyEncryptor)),
        };

        var json = JsonSerializer.Serialize(CreateUser(), EncryptedOptions);

        var ex = Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<User>(json, wrongKeyOptions));

        Assert.Contains("isn't valid ciphertext", ex.Message);
    }

    private static IPropertyEncryptor CreateEncryptor(string key = "Y1qgjUkxxytE5zyGHhQkBLDBf8iNKgtupRAe1v5SQnU=")
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Encryption:Key"] = key })
            .Build();

        return new AesGcmPropertyEncryptor(configuration);
    }

    private static User CreateUser() => new()
    {
        Id = 42,
        Name = "Jane Doe",
        Email = "jane.doe@example.com",
        Ssn = "078-05-1120",
        Address = new Address { Street = "1 Market St", City = "Dublin", PostalCode = "D02 AF30" }
    };

    private sealed class Misconfigured
    {
        [Encrypted]
        public required int Age { get; set; }
    }

    private sealed class Shipment
    {
        public required string TrackingCode { get; set; }

        [Encrypted]
        public required string RecipientEmail { get; set; }
    }

    private sealed class Order
    {
        public required int Id { get; set; }

        public required List<Shipment> Shipments { get; set; }
    }
}
