# Modèle de sécurité

## Objectifs
1. L'interface n'a jamais de droits administrateur.
2. Le composant privilégié ne peut rien faire d'autre que sa liste fixe d'opérations.
3. Aucune donnée personnelle ne quitte la machine.
4. Aucune protection n'est affichée si elle n'existe pas réellement.

## Menaces considérées pour le service privilégié

| Menace | Mesure |
|---|---|
| Un processus quelconque de l'utilisateur envoie des ordres au service | Authentification du client : PID du tube → exécutable = `SecureWall.exe` du dossier d'installation (protégé en écriture) ; compte propriétaire valide |
| Un faux serveur de tube usurpe le service | Le client vérifie que le serveur est `SecureWall.PrivilegedService.exe` à côté de lui avant d'envoyer la moindre requête |
| Accès depuis le réseau | ACL du tube : accès réseau refusé |
| Commande arbitraire / injection | Pas d'opération « exécuter » ; arguments en liste blanche par opération ; aucun shell ; `ProcessRunner` utilise `ArgumentList` ; valeurs PowerShell passées entre quotes échappées |
| Arguments malformés ou énormes | Trames ≤ 1 Mo, arguments ≤ 8 Ko, version de protocole, identifiants bornés, JSON invalide → réponse d'erreur sans plantage |
| Règle dangereuse ou ambiguë | Revalidation complète côté service (nom, ports, adresses, programme existant) ; noms réservés au mode urgence ; règles à nom dupliqué refusées |
| Perte de configuration du pare-feu | Sauvegarde `netsh advfirewall export` avant chaque modification importante ; restauration par nom validé (`^fw-AAAAMMJJ-HHMMSS(-suffixe)?\.wfw$`) dans un dossier protégé (ACL SYSTEM/Admins en écriture) |
| Abus par rafale de requêtes | Opérations modifiantes sérialisées, 60 par minute maximum |
| Dossier d'installation modifiable par un utilisateur standard (copie dans `C:\SecureWall`, droits mal réglés) : la vérification « le client est `SecureWall.exe` de ce dossier » ne prouverait plus rien | Au démarrage, le service contrôle le dossier d'installation et ses parents (propriétaire fiable ; aucun droit d'écriture, de suppression ou de prise de possession pour Utilisateurs / Tout le monde / Utilisateurs authentifiés). Si le contrôle échoue ou est impossible, **toutes** les requêtes sont refusées et l'erreur est journalisée (critique) |
| Faux serveur sous le même nom de tube | ACL du tube sans `CreateNewInstance` pour les utilisateurs ; première instance créée avec `FirstPipeInstance` (le service ne prend jamais un tube déjà occupé : erreur critique journalisée, nouvel essai) ; le client vérifie le serveur via le gestionnaire de services avant tout envoi |
| Saturation du service par des connexions (déni de service) | 16 connexions simultanées au plus (les autres sont coupées aussitôt) ; un client refusé n'a que 2 s pour parler ; lecture limitée à 10 s |
| Blocage de la « sortie de secours » par la limite de fréquence | `EmergencyRestore` n'est jamais soumis à la limite de 60 modifications par minute (il ne fait que retirer les deux règles créées par SecureWall) |
| Dossier de données (`ProgramData\SecureWall`) créé avant l'installation par un utilisateur, ou fichiers déposés dedans (fausse « sauvegarde » du pare-feu, état du mode urgence falsifié, redirection d'écritures de SYSTEM) | `DataDirectoryGuard`, exécuté avant l'ouverture du moindre journal : propriétaire vérifié (sinon le dossier est déplacé de côté puis recréé), droits stricts (SYSTEM + administrateurs ; lecture seule pour les utilisateurs sur la racine et les journaux ; **aucun accès** aux sauvegardes), fichiers de propriétaire non fiable supprimés, chaque anomalie journalisée |
| Remplacement de l'installateur téléchargé entre la vérification et l'exécution avec élévation (le dossier de téléchargement appartient à l'utilisateur) | Fichier ouvert en lecture avec verrou (aucune écriture, renommage ni suppression par un autre processus) et taille + SHA-256 recontrôlés sur ce même flux ; le verrou est conservé jusqu'à la fermeture de l'application || Contournement par variable d'environnement | `SECUREWALL_DEV` n'existe que dans les builds *Debug* |

## Ce que SecureWall ne fait pas
Pas d'injection de DLL, de hook non documenté, de rootkit, de keylogger, d'interception HTTPS, d'installation de certificat racine,
de contournement d'UAC, de désactivation silencieuse de Defender, de persistance cachée, de collecte cachée de données.
Le démarrage avec Windows est une option visible (clé `Run`, désactivable). Les analyses planifiées sont des tâches visibles du
Planificateur de tâches (dossier « SecureWall »).

## Vie privée
Stockage local (`%LocalAppData%\SecureWall`), métadonnées uniquement. La protection cloud de Defender est présentée comme une fonction
de Microsoft Defender. Les journaux ne contiennent ni mot de passe ni contenu de fichier. Purge automatique et effacement manuel.

## Actions toujours confirmées
Désactivation du pare-feu, restauration de quarantaine, création/modification/suppression de règle (si l'option est active),
restauration d'une sauvegarde du pare-feu, mode urgence, activation de l'audit, désactivation d'un programme au démarrage,
effacement de l'historique, import de règles/réglages.
