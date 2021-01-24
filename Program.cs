using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

try
{
    if (args.Length != 2)
    {
        PrintHelp();
        return 1;
    }

    bool encrypt;

    switch (args[0])
    {
        case "e":
            encrypt = true;
            break;

        case "d":
            encrypt = false;
            break;

        default:
            WriteError($"Invalid action '{args[0]}'.");
            PrintHelp();
            return 1;
    }

    var path = args[1];

    if (!File.Exists(path))
    {
        WriteError($"Cannot find file '{path}'.");
        return 1;
    }

    var targetPath = encrypt ? $"{path}.encrypted" : $"{path}.decrypted";

    if (File.Exists(targetPath))
    {
        WriteError($"File '{targetPath}' already exists.");
        return 1;
    }

    Console.WriteLine($"Please enter a password:");
    var password = Console.ReadLine();

    if (password is null)
    {
        return 1;
    }

    byte[] key;

    if (password.Length == 44 && password[^1] == '=')
    {
        key = Convert.FromBase64String(password);
        Console.WriteLine("Parsed the password as a Base64 encoded 32 byte key.");
    }
    else
    {
        key = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        Console.WriteLine("Converted the password to a 32 byte key using SHA-256.");
    }

    using var aes = new AesGcm(key);

    if (encrypt)
    {
        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
        using var random = new RNGCryptoServiceProvider();
        random.GetBytes(nonce);
        var plaintext = await File.ReadAllBytesAsync(path);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        using var stream = File.OpenWrite(targetPath);
        using var binaryWriter = new BinaryWriter(stream);
        binaryWriter.Write(nonce.Length);
        binaryWriter.Write(nonce);
        binaryWriter.Write(tag.Length);
        binaryWriter.Write(tag);
        binaryWriter.Write(ciphertext.Length);
        binaryWriter.Write(ciphertext);
    }
    else
    {
        using var stream = File.OpenRead(path);
        using var binaryReader = new BinaryReader(stream);
        var nonceLength = binaryReader.ReadInt32();
        var nonce = binaryReader.ReadBytes(nonceLength);
        var tagLength = binaryReader.ReadInt32();
        var tag = binaryReader.ReadBytes(tagLength);
        var ciphertextLength = binaryReader.ReadInt32();
        var ciphertext = binaryReader.ReadBytes(ciphertextLength);
        var plaintext = new byte[ciphertextLength];
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        await File.WriteAllBytesAsync(targetPath, plaintext);
    }

    Console.WriteLine($"Written file '{targetPath}'.");
    return 0;
}
catch (Exception ex)
{
    WriteError(ex);
    return 1;
}

static void PrintHelp()
{
    Console.WriteLine();
    Console.WriteLine("Example usage");
    Console.WriteLine("file-encrypter e README.md              Encrypt 'README.md'.");
    Console.WriteLine("file-encrypter d README.md.encrypted    Decrypt 'README.md.encrypted'.");
}

static void WriteError(object message) => Console.Error.WriteLine($"Error: {message}");