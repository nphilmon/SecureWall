using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// Outil du mainteneur : génère la paire de clés ECDSA P-256 et signe les jeux de règles de base.
//   swtool keygen <dossier>                       → baseline-private.pem (à garder secret) + baseline-public.txt (à intégrer à l'application)
//   swtool sign <regles.json> <sortie.json> <baseline-private.pem>
// Le fichier signé est une enveloppe { "Payload": "<JSON des règles>", "Signature": "<base64 ECDSA-SHA256 de Payload en UTF-8>" }.

if (args.Length >= 2 && args[0] == "keygen")
{
    Directory.CreateDirectory(args[1]);
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    File.WriteAllText(Path.Combine(args[1], "baseline-private.pem"), key.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(Path.Combine(args[1], "baseline-public.txt"), Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    Console.WriteLine("Clés générées. Ne partagez JAMAIS baseline-private.pem.");
    return 0;
}

if (args.Length >= 4 && args[0] == "sign")
{
    var payload = File.ReadAllText(args[1], Encoding.UTF8);
    JsonDocument.Parse(payload).Dispose();   // doit être du JSON valide
    using var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(args[3]));
    var sig = key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
    var envelope = JsonSerializer.Serialize(new { Payload = payload, Signature = Convert.ToBase64String(sig) }, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(args[2], envelope, new UTF8Encoding(false));
    Console.WriteLine("Jeu de règles signé : " + args[2]);
    return 0;
}

// swtool manifest <installateur.exe> <version> <url-installateur> <notes.txt|texte> <sortie.json> <cle-privee.pem>
// Produit le manifeste signé de mise à jour (taille et SHA-256 calculés sur l'installateur).
if (args.Length >= 7 && args[0] == "manifest")
{
    var installer = args[1];
    var url = args[3];
    var notes = File.Exists(args[4]) ? File.ReadAllText(args[4], Encoding.UTF8) : args[4];
    var info = new FileInfo(installer);
    string sha;
    await using (var fs = File.OpenRead(installer)) sha = Convert.ToHexString(await SHA256.HashDataAsync(fs));
    var payload = JsonSerializer.Serialize(new
    {
        Format = "SecureWall.Update", Version = args[2], Published = DateTime.UtcNow.ToString("yyyy-MM-dd"),
        Notes = notes, InstallerUrl = url, Sha256 = sha, Size = info.Length,
    }, new JsonSerializerOptions { WriteIndented = true });
    using var key = ECDsa.Create();
    key.ImportFromPem(File.ReadAllText(args[6]));
    var sig = key.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256);
    File.WriteAllText(args[5], JsonSerializer.Serialize(new { Payload = payload, Signature = Convert.ToBase64String(sig) }, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
    Console.WriteLine($"Manifeste signé : {args[5]} (v{args[2]}, {info.Length:N0} octets, SHA-256 {sha})");
    return 0;
}

Console.WriteLine("Usage : swtool keygen <dossier> | swtool sign <regles.json> <sortie.json> <cle-privee.pem> | swtool manifest <installateur.exe> <version> <url> <notes> <sortie.json> <cle-privee.pem>");
return 1;
