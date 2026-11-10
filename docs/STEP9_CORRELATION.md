# AI-Powered SOC Lab — Étape 9 : corrélation Sysmon / PowerShell

Date : 10 novembre 2026.

## État de validation

- Validé par l'utilisateur : les requêtes SPL parent et PowerShell 4104 s'exécutent dans Splunk.
- Validé localement : 15 tests unitaires (`test_splunk_triage` + `test_soc_correlation`).
- **Validation de terrain ensuite rapportée** : le moteur de corrélation a fonctionné sur les événements réels, avec `missing_evidence: []` pour certaines alertes. D’autres conservent `parent_process_event` ; l’hypothèse d’un démarrage de parent avant l’activation de Sysmon est plausible mais non confirmée.

## Installation

Place `soc_correlation.py`, `test_soc_correlation.py` et le `splunk_connector.py` mis à jour à la racine de `ai_powered_soc_lab/`, à côté de `soc_models.py`, `soc_normalization.py`, `splunk_triage.py` et `triage.py`.

Le `splunk_connector.py` actualisé ajoute `ProcessId` et `ParentProcessId` aux champs récupérés via l'API. Il ne change pas la signature de `fetch_detections()`.

## Tester hors ligne

```powershell
python -m unittest -v test_splunk_triage test_soc_correlation
```

## Corréler les événements réels

1. Depuis WIN-LAB, exécute le scénario bénin `powershell.exe -NoProfile -EncodedCommand ...` de l'étape 4.
2. Sur le PC du projet, exécute :

```powershell
python .\soc_correlation.py --insecure-lab
```

`--insecure-lab` **désactive la vérification du certificat TLS** et doit être réservé au réseau de laboratoire de confiance. Configurer une CA locale pour le fonctionnement durable.

## Structure retournée

- `alert_envelope.synthetic = false` pour les événements réellement retournés par Splunk.
- `alert_envelope.evidence[]` : événement Sysmon enfant, événement parent retrouvé et fragments PowerShell 4104 corrélés.
- `alert_envelope.missing_evidence[]` : conserve `parent_process_event` ou `powershell_script_block` quand la preuve n'est pas suffisante.
- `triage.evidence[].decoded_command` : texte décodé sans exécution du code.

## Critères de correspondance

**Parent** : même hôte, Sysmon ID 1, `ProcessGuid` du parent égal au `ParentProcessGuid` de l'enfant, création avant celle de l'enfant. Recherche historique limitée à 7 jours.

**PowerShell 4104** : même hôte, `Execution ProcessID` égal au `ProcessId` du processus PowerShell Sysmon, horodatage dans la fenêtre de -2 à +300 secondes autour de sa création. La preuve est dite complète seulement si tous les fragments (1..`MessageTotal`) sont présents pour un même `ScriptBlockId`.

## Limites connues

- Le rapprochement d'un 4104 avec Sysmon par PID + hôte + temps reste une **corrélation heuristique** : un PID peut être réutilisé. Pour un SOC réel, tenir compte des événements de terminaison de processus (Sysmon ID 5), des identifiants de session et d'une synchronisation temporelle fiable.
- La requête PowerShell récupère au maximum 100 fragments par détection. Une forte activité peut imposer une pagination et une stratégie de sélection plus précise.
- Une absence de preuve dans les résultats ne prouve pas l'absence d'activité : rétention des journaux, filtrage et configuration Sysmon/PowerShell peuvent intervenir.
- Les scripts 4104 peuvent contenir des informations sensibles : ne pas publier les JSON bruts dans GitHub, ni dans les captures LinkedIn.
- Le connecteur reste en lecture seule et n'effectue aucune action de remédiation.

## Étape suivante

Ajouter des tests d'intégration sur des événements réels pseudonymisés, vérifier les champs `missing_evidence`, puis préparer la création d'une alerte SOC dans le backend FastAPI.
