# Limitations et pistes d'évolution

Voir aussi la section « Limitations connues » du README.

## Non vérifié sur cette machine de développement
- Windows 10 : le code vise Windows 10 2004+ et Windows 11, mais seuls les tests sur Windows 11 ont été effectués.
- Opérations du service **avec droits administrateur** (création/suppression réelle de règles, mode urgence, restauration de
  quarantaine, audit des blocages, trafic TCP par connexion) : la logique et la validation sont testées sur des doublures et le
  protocole de tube a été testé de bout en bout sans élévation (authentification, refus, validation) ; l'exécution réelle des
  écritures demande un test manuel dans une session administrateur (voir README → Exécution).
- Installateur : le script Inno Setup est fourni ; sa compilation exige Inno Setup 6.

## Pistes
- Filtrage préventif des connexions (pilote WFP signé) pour l'alerte « avant la première connexion ».
- Statistiques par processus en temps réel (ETW *Microsoft-Windows-Kernel-Network*, droits administrateur).
- Surveillance de dossiers de téléchargement avec analyse automatique par Defender.
- Entrée de menu contextuel « Analyser avec SecureWall » (clé `HKCU\Software\Classes`).
- Traduction de l'interface.
