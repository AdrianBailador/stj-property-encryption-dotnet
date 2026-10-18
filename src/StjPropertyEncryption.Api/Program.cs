using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using StjPropertyEncryption.Api.Encryption;
using StjPropertyEncryption.Api.Models;
using StjPropertyEncryption.Api.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IPropertyEncryptor, AesGcmPropertyEncryptor>();

var app = builder.Build();

var encryptor = app.Services.GetRequiredService<IPropertyEncryptor>();

// "Before": the default resolver — whatever is in the CLR object goes out as-is.
var plainOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);

// "After": a resolver that rewrites Get/Set for every [Encrypted] property at the
// serialization boundary, without touching User or Address at all.
var encryptedOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web)
{
    TypeInfoResolver = new DefaultJsonTypeInfoResolver()
        .WithAddedModifier(EncryptionTypeInfoModifier.Create(encryptor))
};

var users = new Dictionary<int, User>
{
    [42] = new User
    {
        Id = 42,
        Name = "Jane Doe",
        Email = "jane.doe@example.com",
        Ssn = "078-05-1120",
        Address = new Address { Street = "1 Market St", City = "Dublin", PostalCode = "D02 AF30" }
    }
};

app.MapGet("/users/{id:int}", (int id) =>
    users.TryGetValue(id, out var user)
        ? Results.Text(JsonSerializer.Serialize(user, plainOptions), "application/json")
        : Results.NotFound());

app.MapGet("/secure/users/{id:int}", (int id) =>
    users.TryGetValue(id, out var user)
        ? Results.Text(JsonSerializer.Serialize(user, encryptedOptions), "application/json")
        : Results.NotFound());

app.Run();

public partial class Program;
