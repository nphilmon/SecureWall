# SecureWall Security

Console de sécurité Windows moderne, construite **au-dessus** de Microsoft Defender Antivirus et de Windows Defender Firewall.
SecureWall ne remplace aucun composant de Windows : il affiche leur état réel, déclenche leurs fonctions officielles et rend les
informations de sécurité plus lisibles.

> **Principe directeur** — rien n'est simulé. Si une protection dépend d'un composant Windows désactivé ou indisponible, SecureWall l'affiche
> tel quel ; il n'a ni moteur antivirus propre, ni pilote, ni injection, ni interception.

## Sommaire

1. [Fonctions](#fonctions)
2. [Prérequis](#prérequis)
3. [Architecture](#architecture)
4. [Compilation](#compilation)
5. [Exécution](#exécution)
6. [Le service privilégié](#le-service-privilégié)
7. [Base de données](#base-de-données)
8. [Sécurité](#sécurité)
9. [Limitations connues](#limitations-connues)
10. [Installation](#installation)
11. [Tests](#tests)
12. [Dépannage](#dépannage)

## Fonctions

| Page | Contenu | Source des données |
|---|---|---|
| Tableau de bord | État général, antivirus, pare-feu, débit réseau, alertes récentes | Defender (WMI), Pare-feu (COM), IP Helper |
| Antivirus | État réel de la protection (temps réel, cloud, comportement, PUA, téléchargements), signatures, exclusions (lecture) | `root\Microsoft\Windows\Defender` |
| Analyses | Rapide, complète, personnalisée (fichier/dossier/disque), annulation, analyses planifiées | `MpCmdRun.exe`, Planificateur de tâches |
| Menaces | Historique de protection avec filtres (actif, supprimé, bloqué, quarantaine, autorisé) | `MSFT_MpThreat`, `MSFT_MpThreatDetection` |
| Quarantaine | Éléments isolés, restauration (avec avertissement), détails | Defender via le service privilégié |
| Processus | Nom, PID, utilisateur, chemin, éditeur, signature, CPU, RAM, réseau, lancement ; faits (non signé, chemin inhabituel…) | API Windows + `Get-AuthenticodeSignature` |
| Connexions | TCP/UDP par processus, filtres (application, protocole, port, IP, état), octets par connexion TCP IPv4 | `GetExtendedTcpTable`, ESTATS |
| Applications | Programmes ayant utilisé le réseau, règle actuelle, autoriser/bloquer/créer une règle | Base SQLite + pare-feu |
| Pare-feu | Profils, réseaux, activation avec confirmation, sauvegardes, audit des blocages, **mode urgence** | `INetFwPolicy2`, `netsh advfirewall export/import` |
| Règles | Lecture, création (assistant en 9 étapes), modification, duplication, activation, suppression, import/export JSON | `INetFwRule` |
| USB | Détection des supports amovibles, périphériques connus, analyse Defender | WMI + base SQLite |
| Démarrage | Run (HKCU/HKLM/Wow6432Node) et dossiers Démarrage, activation/désactivation confirmée | Registre, `StartupApproved` |
| Historique | Événements de sécurité, journal d'audit, analyses, connexions bloquées (pagination) | SQLite |
| Statistiques | Applications les plus connectées, connexions par heure, ports, destinations, menaces, analyses (24 h / 7 j / 30 j) | SQLite |
| Centre de sécurité | Antivirus, Pare-feu, Réseau, Processus, USB, Protection Windows : *Protégé / Attention / Action requise* | Données réelles uniquement |
| Paramètres | Démarrage, zone de notification, notifications, thème clair/sombre/système, confidentialité, sauvegarde des réglages | SQLite |

Autres éléments : assistant de premier démarrage (8 étapes), icône de zone de notification (Ouvrir, Protection, Analyse rapide, Pare-feu,
Couper/Restaurer Internet, Paramètres, Quitter), notifications Windows (toasts) qui ouvrent la page concernée, alerte optionnelle
« nouvelle application réseau » (autoriser/bloquer une fois ou toujours), surveillance des changements sensibles.

## Règles de base du pare-feu et mises à jour

Page **Règles → « Règles de base… »** : jeu de règles de durcissement (Telnet, TFTP, SMB/NetBIOS et Bureau à distance exposés à Internet,
WinRM, UPnP/SSDP) fourni avec l'application. Aperçu, cases à cocher, confirmation, sauvegarde automatique du pare-feu, création par le
service privilégié. Les règles existantes sont signalées « Déjà présente ».

**Mise à jour** : Bitdefender ne publie aucun flux public de règles utilisable par une application tierce ; SecureWall utilise donc un
fichier **signé en ECDSA P-256** que vous publiez vous-même (ou qu'un tiers de confiance publie) :

1. `dotnet run --project src\SecureWall.Tools -- keygen installer\keys` (une fois ; la clé privée reste secrète, dossier ignoré par git) ;
   copiez `baseline-public.txt` dans `BaselineRulesService.PublicKeyBase64` puis recompilez.
2. Modifiez le JSON des règles (augmentez `Version`), puis `dotnet run --project src\SecureWall.Tools -- sign regles.json baseline-rules.signed.json installer\keysaseline-private.pem`.
3. Publiez le fichier signé sur GitHub ; dans l'application, saisissez son adresse `https://raw.githubusercontent.com/...` et cliquez sur
   « Rechercher une mise à jour ». Seuls HTTPS et `raw.githubusercontent.com` sont acceptés ; téléchargement uniquement sur clic, 256 Ko max ;
   signature, format et chaque règle sont revalidés (aucune règle d'autorisation entrante, aucun programme ciblé).

## Signature du logiciel (Authenticode)

`build-installer.ps1` signe par défaut (SHA-256, horodatage DigiCert) : `SecureWall.exe`, `SecureWall.PrivilegedService.exe` et les DLL
`SecureWall*.dll` (jamais les bibliothèques Microsoft ou tierces), puis l'installateur **et** le désinstalleur via Inno Setup. Option `-NoSign`
pour construire sans signer. Aucun `signtool.exe` n'est nécessaire (cmdlet `Set-AuthenticodeSignature` de Windows PowerShell).

- **Certificat auto-signé (actuel)** : `installer\New-SigningCertificate.ps1` (une fois ; `-Subject`, `-Years`). Créé dans votre magasin personnel
  uniquement ; `installer\keys\` (ignoré par git) reçoit le `.cer` public, une sauvegarde `.pfx` et son mot de passe. **Sauvegardez ce dossier
  hors du PC.** Windows affiche « éditeur : SecureWall Security » mais SmartScreen avertit tant que le certificat n'est pas approuvé. L'installateur
  n'ajoute jamais de certificat sur la machine. Pour faire confiance à ce certificat sur un PC précis (choix de son propriétaire, en administrateur) :
  `Import-Certificate installer\keys\SecureWall-codesign.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher` (et `...\Root` pour que la
  chaîne soit reconnue).
- **Vrai certificat** (OV/EV d'une autorité reconnue, ou jeton matériel) : aucun changement de script. Définir avant le build
  `SECUREWALL_SIGN_PFX` + `SECUREWALL_SIGN_PFX_PASSWORD` (fichier .pfx) **ou** `SECUREWALL_SIGN_THUMBPRINT` (certificat du magasin, jeton
  compris) ; ces variables ont priorité sur le certificat auto-signé. Horodatage modifiable avec `SECUREWALL_SIGN_TIMESTAMP`. Un certificat EV
  supprime l'avertissement SmartScreen immédiatement, un certificat OV après une période de réputation.
- **Ordre de publication** : construire (donc signer) l'installateur **avant** de générer le manifeste de mise à jour : celui-ci contient le
  SHA-256 et la taille du fichier signé.
## Mises à jour de l'application

**Paramètres → « Mises à jour de l'application »** : la recherche ne se fait que sur clic. Le *manifeste* est une enveloppe signée avec la même
clé ECDSA P-256 que le jeu de règles (clé publique intégrée à l'application) ; l'installateur n'est téléchargé que depuis GitHub (HTTPS,
`github.com` et `*.githubusercontent.com`, chaque redirection est contrôlée) ; sa taille et son SHA-256 viennent du manifeste signé ; le fichier
est supprimé au moindre écart ; l'installateur ne se lance qu'après confirmation, avec l'autorisation Windows (UAC).

Publier une version (mainteneur) :

1. Fixer la version dans `src\Directory.Build.props` et `installer\SecureWall.iss`, puis `installer\build-installer.ps1`.
2. Créer une publication GitHub et y joindre `publish\SecureWall-Setup-X.Y.Z.exe`.
3. `dotnet run --project src\SecureWall.Tools -- manifest publish\SecureWall-Setup-X.Y.Z.exe X.Y.Z <url-de-l-installateur-dans-la-publication> "<notes>" update.signed.json installer\keys\baseline-private.pem`
4. Publier `update.signed.json` dans le dépôt ; son adresse `https://raw.githubusercontent.com/…/update.signed.json` est celle à saisir dans l'application.

## Prérequis

- Windows 10 version 2004 (build 19041) ou ultérieure, ou Windows 11 — **64 bits**.
- Pour **compiler** : SDK .NET 8 (`winget install Microsoft.DotNet.SDK.8`). Visual Studio 2022 17.8+ est facultatif.
- Pour **fabriquer l'installateur** : Inno Setup 6 (`winget install JRSoftware.InnoSetup`).
- Pour **utiliser** SecureWall avec toutes ses fonctions : Microsoft Defender actif (ou au moins présent) et le service privilégié démarré.

## Architecture

```
SecureWall.sln
src/
  SecureWall.Core/              Modèles, interfaces, enums, DTO, validation, logique pure (sans dépendance Windows) — net8.0
  SecureWall.Infrastructure/    SQLite, journaux, réglages, WMI/PowerShell/Process, notifications (toasts + zone de notif.), client du tube
  SecureWall.Security/          Antivirus/ Firewall/ Network/ Processes/ Devices/ Monitoring/  (aucune dépendance WPF)
  SecureWall.PrivilegedService/ Service Windows : serveur de tube nommé, liste blanche, gestionnaires Firewall/ Antivirus/ SystemOperations/
  SecureWall.App/               Interface WPF (MVVM, CommunityToolkit.Mvvm) : Views, ViewModels, Controls, Converters, Themes
  SecureWall.Tests/             xUnit : 156 tests, tous sans effet sur la machine
installer/                      Script Inno Setup + scripts de publication / installation du service
docs/                           Notes d'architecture, modèle de sécurité, limitations
```

Dépendances : `App → Security → Infrastructure → Core` ; `PrivilegedService → Security`. La logique de sécurité ne dépend jamais de l'interface.
Les services sont derrière des interfaces (`IDefenderService`, `IFirewallPolicy`, `IPrivilegedClient`, `ISecurityStore`…), ce qui permet
de les remplacer par des doublures dans les tests.

Détails dans [docs/architecture.md](docs/architecture.md).

## Compilation

```powershell
dotnet restore
dotnet build SecureWall.sln -c Release
dotnet test src\SecureWall.Tests
```

Publication complète (application + service, autonome, x64) puis installateur :

```powershell
powershell -ExecutionPolicy Bypass -File installer\build-installer.ps1
# → publish\SecureWall-Setup-2.0.2.exe
# Publication seule : ... build-installer.ps1 -SkipInstaller   → publish\SecureWall\
```

## Exécution

**Développement** (sans installer le service) :

```powershell
dotnet run --project src\SecureWall.App
```

L'interface fonctionne en lecture seule (Defender, règles, connexions, processus…). Les opérations qui exigent des droits
administrateur affichent « Le service privilégié SecureWall n'est pas démarré ».

Pour tester les opérations privilégiées en développement, lancez le service dans une console **administrateur** :

```powershell
$env:SECUREWALL_DEV = "1"        # Debug uniquement : désactive la vérification du chemin des binaires (jamais compilé en Release)
dotnet run --project src\SecureWall.PrivilegedService
```

… puis l'application dans une autre console avec la même variable. Les builds *Release* ignorent `SECUREWALL_DEV` : le service
n'accepte alors que `SecureWall.exe` situé dans son propre dossier.

Arguments de ligne de commande de l'application : `--minimized` (démarre dans la zone de notification), `--page <Page>` (ouvre une page),
`--scheduled-scan <Quick|Full|Custom> [--path <chemin>]` (analyse planifiée sans interface, utilisée par le Planificateur de tâches),
`--restart` (relance après élévation).

## Le service privilégié

`SecureWall.PrivilegedService` est un service Windows (`SecureWallPrivilegedService`, compte système, démarrage automatique).
**L'interface ne tourne jamais en administrateur** ; elle demande au service d'exécuter les seules opérations qui l'exigent.

- **Canal** : tube nommé local `SecureWall.Privileged.v1` ; ACL : SYSTEM et administrateurs (contrôle total), utilisateurs authentifiés
  (lecture/écriture), **réseau refusé**. Trames : longueur (4 octets) + JSON UTF-8, 1 Mo maximum.
- **Authentification du client** : le service lit le PID du client (`GetNamedPipeClientProcessId`), vérifie que le propriétaire du
  processus est un compte réel et que l'exécutable est **`SecureWall.exe` situé dans le dossier du service** (dossier d'installation,
  modifiable uniquement par les administrateurs). **Réciproquement**, le client refuse de parler à un serveur de tube qui n'est pas
  le `SecureWall.PrivilegedService.exe` installé à côté de lui.
- **Liste blanche** (`PrivilegedOperation`) : profils du pare-feu, création/modification/suppression/activation de règles,
  sauvegarde/liste/restauration, lecture du journal des blocages, audit des blocages, mode urgence (couper/restaurer/état),
  restauration de quarantaine, traitement des menaces actives, trafic TCP par connexion, activation d'un démarrage « machine ».
  **Aucune opération n'accepte une commande, un script ou un chemin d'exécutable à lancer.**
- **Validation stricte** : jeu d'arguments exact par opération, tailles bornées, règles revalidées côté service (nom, ports, adresses,
  programme existant), noms de sauvegarde par expression régulière, profils ∈ {1,2,4}, règles du mode urgence protégées,
  noms de règle ambigus refusés, limitation de fréquence des modifications.
- **Filet de sécurité** : une sauvegarde complète du pare-feu (`netsh advfirewall export`) précède toute modification importante ;
  elle est restaurable depuis la page Pare-feu. Les modifications sont sérialisées et journalisées (journal du service + `AuditLogs`).

Voir [docs/security-model.md](docs/security-model.md).

## Base de données

SQLite : `%LocalAppData%\SecureWall\securewall.db` (mode WAL). Tables : `Applications`, `Connections`, `FirewallEvents`,
`AntivirusScans`, `Threats`, `Devices`, `SecurityEvents`, `AuditLogs`, `Settings` (+ index sur les dates et les clés de jointure).
Seules des **métadonnées** sont stockées (noms, chemins, adresses, dates) : jamais le contenu des fichiers, ni mot de passe.
Conservation configurable (90 jours par défaut) avec purge automatique ; « Effacer l'historique » dans Paramètres.

## Sécurité

Interdits par conception : injection de DLL, hooks non documentés, rootkit, keylogger, interception HTTPS / MITM, certificats racine,
contournement d'UAC, désactivation silencieuse de Defender, persistance cachée, collecte cachée de données.
Ce que fait SecureWall : API documentées uniquement (WMI Defender, `MpCmdRun`, `INetFwPolicy2`, IP Helper, Planificateur de tâches,
`netsh`, `auditpol`, journal d'événements), actions sensibles **toujours confirmées**, aucun envoi de données hors de la machine.

Un fichier non signé, un éditeur inconnu ou un chemin inhabituel sont affichés comme des **faits**, jamais comme une preuve de
malveillance ; seule une détection de Microsoft Defender est présentée comme une menace.

## Limitations connues

- **Pas d'interception en temps réel des connexions.** SecureWall observe les connexions existantes (sondage) ; l'alerte « nouvelle
  application » intervient après la première connexion observée. Un blocage préventif exigerait un pilote WFP (non fourni, car
  SecureWall n'installe aucun pilote).
- **Connexions bloquées** : Windows ne les journalise que si l'audit « Plateforme de filtrage » est activé (bouton explicite dans
  *Pare-feu*) ; sans audit, le compteur affiche « Non journalisées ».
- **Octets par connexion** : TCP IPv4 uniquement, comptés depuis l'activation des statistiques ESTATS par le service ; UDP/IPv6 : « — ».
- **Progression des analyses** : Defender ne publie ni pourcentage ni fichier courant ; la barre est indéterminée pour les analyses
  rapide/complète. Le nombre de fichiers n'est connu que pour les analyses personnalisées.
- **Quarantaine** : Windows n'expose pas d'API de suppression d'un élément déjà en quarantaine ; SecureWall ouvre l'historique de
  Windows Security pour cela (Defender purge de toute façon après 90 jours). La restauration passe par `MpCmdRun -Restore`.
- **Exclusions Defender** : lisibles uniquement avec des droits administrateur (restriction de Windows) ; SecureWall n'en crée jamais.
- **Impact au démarrage** : non communiqué par Windows via une API publique.
- Les analyses planifiées s'exécutent lorsque l'utilisateur est connecté (tâche au niveau du compte, sans mot de passe).
- Langue : français uniquement pour l'instant.
- Les tests manuels du service avec droits administrateur (écritures réelles dans le pare-feu) ne sont pas automatisés : les tests
  automatiques valident la validation et la logique sur des doublures, sans jamais modifier la machine.

## Installation

Voir `installer\SecureWall.iss`. L'installateur :

- installe en `Program Files\SecureWall` (x64, privilèges administrateur) ;
- crée le service `SecureWallPrivilegedService` (démarrage automatique, redémarrage en cas d'échec) ;
- ajoute un raccourci du menu Démarrer, un raccourci Bureau facultatif, et — facultativement — le démarrage avec Windows ;
- **ne modifie aucun paramètre de sécurité** (Defender, pare-feu, certificats…) ;
- à la désinstallation : arrête et supprime le service ; **conserve** vos données (`%LocalAppData%\SecureWall`) et les sauvegardes
  du pare-feu (`%ProgramData%\SecureWall\FirewallBackups`).

Installation manuelle du service : `installer\Install-Service.ps1` (PowerShell administrateur).

## Tests

`dotnet test src\SecureWall.Tests` — 156 tests : `FirewallServiceTests`, `DefenderServiceTests`, `DatabaseTests`, `RuleValidationTests`,
`NetworkMonitorTests`, `SecurityEventTests`, `PrivilegedServiceTests` (liste blanche, validation, trames).
Les tests utilisent des doublures (faux pare-feu, fausse passerelle Defender, base SQLite temporaire) et n'effectuent **aucune
modification destructive** sur la machine de développement.

## Dépannage

- *« Le service privilégié n'est pas démarré »* : `Get-Service SecureWallPrivilegedService` ; journaux dans `%ProgramData%\SecureWall\logs`.
- *Pas de notification Windows* : vérifiez l'assistance de concentration de Windows ; SecureWall se replie sur une bulle de la zone de notification.
- Journaux de l'application : `%LocalAppData%\SecureWall\logs`.
