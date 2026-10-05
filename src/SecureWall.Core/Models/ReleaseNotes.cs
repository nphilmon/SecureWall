using SecureWall.Core.Enums;

namespace SecureWall.Core.Models;

/// <summary>Une nouveauté ou un correctif ; Page permet d'ouvrir directement l'écran concerné.</summary>
public sealed record ReleaseFeature(string Category, string Title, string Description, AppPage? Page = null, string? PageLabel = null, string? PageParameter = null);

public sealed record ReleaseEntry(string Version, string Date, string Title, IReadOnlyList<ReleaseFeature> Features);

/// <summary>Notes de version affichées dans la page « Nouveautés » (la plus récente en premier).</summary>
public static class ReleaseNotes
{
    public const string New = "Nouveau";
    public const string Improved = "Amélioré";
    public const string Fixed = "Corrigé";
    public const string Security = "Sécurité";

    public static readonly IReadOnlyList<ReleaseEntry> All = new[]
    {
        new ReleaseEntry("2.0.2", "5 octobre 2026", "Mises à jour plus claires et désinstallation fiable", new ReleaseFeature[]
        {
            new(Improved, "Recherche de mise à jour plus lisible",
                "Un indicateur animé s'affiche pendant la recherche, le résultat est coloré (vert : à jour, bleu : nouvelle version, rouge : erreur) et l'heure de la dernière vérification est indiquée à chaque clic, même si le résultat ne change pas.",
                AppPage.Settings, "Ouvrir les paramètres"),
            new(Improved, "Adresse des mises à jour préremplie",
                "L'adresse officielle du manifeste signé (dépôt GitHub du projet) est proposée par défaut : plus rien à saisir. Seule la recherche reste à votre initiative."),
            new(Fixed, "Désinstallation complète",
                "SecureWall et son service sont fermés avant la suppression des fichiers. Auparavant, une application restée dans la zone de notification pouvait laisser le dossier d'installation sur le disque."),
        }),
        new ReleaseEntry("2.0.1", "5 octobre 2026", "Cartes, DNS, mode urgence et mises à jour", new ReleaseFeature[]
        {
            new(New, "Carte des connexions",
                "Voyez dans quels pays se trouvent les serveurs contactés par vos applications : carte du monde colorée selon le nombre de connexions, tableau par pays, détail par application et par adresse. " +
                "La localisation en ligne est désactivée par défaut : elle n'envoie que des adresses IP publiques, après votre confirmation.", AppPage.Map, "Ouvrir la carte"),
            new(New, "Gestion du DNS",
                "Consultez les serveurs DNS de chaque carte réseau (avec reconnaissance de Cloudflare, Google, Quad9…), changez-les en un clic, revenez à la configuration automatique ou videz le cache DNS. " +
                "Un serveur public inconnu est signalé.", AppPage.Dns, "Ouvrir la page DNS"),
            new(New, "Détail des connexions bloquées",
                "Filtres par période, direction et recherche, résumé des applications, adresses et ports les plus fréquents, explication en langage courant, nom d'hôte à la demande (DNS inverse) et export CSV.",
                AppPage.History, "Voir les connexions bloquées", "blocked"),
            new(Improved, "Mode urgence plus sûr",
                "Rétablissement automatique d'Internet après 5 min, 15 min, 30 min, 1 h ou 4 h, avec compte à rebours dans l'en-tête. Si la création des règles échoue à moitié, rien n'est conservé, et l'échéance survit à un redémarrage.",
                AppPage.Firewall, "Ouvrir le pare-feu"),
            new(New, "Mises à jour vérifiées de l'application",
                "À votre demande uniquement : manifeste signé, téléchargement limité à GitHub, empreinte SHA-256 vérifiée avant tout lancement de l'installateur.", AppPage.Settings, "Ouvrir les paramètres"),
            new(Fixed, "Mode urgence et règles du pare-feu",
                "Le mot-clé « Internet » refusé par Windows est converti en plages d'adresses, et les règles sans programme précis ne provoquent plus d'erreur. Les cinq règles de base (SMB, RDP, WinRM, UPnP) fonctionnent aussi."),
            new(Fixed, "Vérification du service privilégié",
                "L'application ne pouvait pas vérifier l'identité du service sans droits administrateur : elle interroge maintenant le gestionnaire de services Windows."),
            new(Security, "Service privilégié durci",
                "Le service refuse toute requête si son dossier d'installation est modifiable par un utilisateur standard, ne peut plus être imité par un faux tube nommé ni saturé par des connexions en rafale, et « Restaurer Internet » n'est jamais bloqué. " +
                "Le dossier de données est contrôlé (propriétaire, droits, fichiers étrangers supprimés), et l'installateur téléchargé est verrouillé puis revérifié juste avant son lancement. Les nouvelles opérations (DNS, durée du mode urgence) n'acceptent que des arguments précis, revalidés côté service."),
        }),
        new ReleaseEntry("1.0.0", "Version initiale", "SecureWall Security", new ReleaseFeature[]
        {
            new(New, "Protection au quotidien",
                "Tableau de bord, antivirus (Microsoft Defender), pare-feu Windows avec règles, connexions et processus, périphériques USB, programmes au démarrage, historique et statistiques, et mode urgence."),
        }),
    };

    public static ReleaseEntry? For(string version) => All.FirstOrDefault(e => e.Version == version);

    /// <summary>Vrai si la page Nouveautés doit s'ouvrir seule : la version a changé depuis la dernière visite et elle a des notes.</summary>
    public static bool ShouldShow(string? lastSeenVersion, string currentVersion) =>
        !string.Equals(lastSeenVersion ?? "", currentVersion, StringComparison.Ordinal) && For(currentVersion) != null;
}
