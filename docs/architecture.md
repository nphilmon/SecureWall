# Architecture

## Couches

```
SecureWall.App  (WPF, MVVM)
   │  ViewModels ── interfaces Core ──►  Views / Controls / Converters / Themes
   ▼
SecureWall.Security  (logique métier de sécurité, sans WPF)
   Antivirus/  Firewall/  Network/  Processes/  Devices/  Monitoring/
   ▼
SecureWall.Infrastructure  (accès au système)
   Database/ (SQLite)  Windows/ (WMI, PowerShell, ProcessRunner, tube)  Notifications/  Logging/  Configuration/
   ▼
SecureWall.Core  (modèles, interfaces, DTO, validation, logique pure)

SecureWall.PrivilegedService ──► Security, Infrastructure, Core   (processus séparé, compte système)
```

L'interface n'appelle jamais `netsh`, WMI ou le pare-feu directement : elle passe par des interfaces (`IFirewallService`,
`IDefenderService`…), implémentées dans `SecureWall.Security`. Les **écritures** sensibles sont envoyées au service via
`IPrivilegedClient` ; les **lectures** se font directement (elles ne demandent pas de droits).

## Microsoft Defender

`DefenderGateway` est le seul point d'accès : classes WMI `MSFT_MpComputerStatus`, `MSFT_MpPreference`, `MSFT_MpThreat`,
`MSFT_MpThreatDetection` (espace `root\Microsoft\Windows\Defender`) et `MpCmdRun.exe` (`-Scan`, `-Scan -Cancel`, `-SignatureUpdate`).
`DefenderService` expose `GetStatusAsync`, `GetRealtimeProtectionStatusAsync`, `GetSignatureVersionAsync`, `UpdateSignaturesAsync`,
`StartQuickScanAsync`, `StartFullScanAsync`, `StartCustomScanAsync`, `GetThreatsAsync`, `GetProtectionHistoryAsync`.
`ThreatSync` recopie les détections dans SQLite et déclenche les notifications (la première synchronisation est silencieuse).

## Pare-feu

`ComFirewallPolicy` (INetFwPolicy2 / INetFwRule) est partagé par l'application (lecture) et le service (écriture).
`FirewallService` (état, profils, sauvegardes), `FirewallRuleService` (CRUD, import/export JSON) et `NetworkProfileService`
(`MSFT_NetConnectionProfile`) s'appuient sur `IFirewallPolicy` + `IPrivilegedClient`. `EmergencyExecutor` (côté service) crée deux
règles de blocage « Internet » réversibles dans le groupe « SecureWall Emergency » et mémorise l'état.

## Réseau et processus

`IpHelper` lit les tables TCP/UDP (IPv4/IPv6) avec PID. `NetworkMonitor` : débit (statistiques d'interfaces), instantanés de connexions,
enregistrement des applications et des connexions externes (dédoublonnage 10 min), détection d'une première connexion externe après une
phase d'apprentissage de 90 s. `ProcessService` agrège processus, propriétaire, CPU, mémoire, signature (cache asynchrone) et connexions.

## Surveillance

`SecurityMonitor` compare des instantanés (Defender, profils du pare-feu, empreinte des règles, exclusions, démarrage) à une base de
référence persistée (`baseline.json`) via `SecurityChangeDetector` (logique pure, testée). La première exécution ne génère aucune alerte.
`SecurityStateService` fournit l'état global (`GlobalStateEvaluator`) à partir de faits réels.

## Interface

MVVM avec CommunityToolkit.Mvvm. `MainViewModel` implémente `INavigator` ; les pages sont des `PageViewModel` (singletons) résolus par
injection ; `Reconciler.Sync` met à jour les listes sur place (sélection et défilement conservés) ; les tableaux utilisent la
virtualisation de lignes WPF et `ICollectionView` pour le filtrage. Thèmes : dictionnaires `Light.xaml` / `Dark.xaml` (remplacés à chaud).
Gestion d'erreurs : `PageViewModel.GuardAsync`, gestionnaires globaux (`DispatcherUnhandledException`, tâches non observées), journal fichier.
