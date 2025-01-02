[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_frankenstrings-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-frankenstrings)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-frankenstrings)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-frankenstrings)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-frankenstrings)](./LICENSE)
# FrankenStrings Service

This service performs file and IOC extractions using pattern matching, simple encoding decoder and script deobfuscators.

BALBUZARD: BSD 2-Clause Licence, see top of balbuzard code files

## Service Details

1. String Extraction:
    * ASCII and unicode string IOC checking. (see patterns.py)
    * Balbuzard's bbcrack level 1 (*level 2 for deep scan*) XOR transform modules. Matches specific IOCs only (see patterns.py, bbcrack.py)
    * Base64 string extract

2. File Extraction:
    * Balbuzard's bbcrack level 1 (*level 2 for deep scan*) XOR transform modules. (Searches for PE files only)
    * Base64 module search for file types of interest (see frankenstrings.py)
    * Embedded PE file extraction
    * Unicode, Hex, Ascii-Hex extraction modules (for possible shellcode)

**When not in deep scan mode, this AL service will skip detection modules based on a submitted file's size
(to prevent service backlog and timeouts). The defaults are
intentionally set at low sizes. Filters can be easily changed in the service configuration,
based on the amount of traffic/hardware your AL instance is running.**

### Service Configuration

- max_size: Maximum size of submitted file for this service
- max_length: String length maximum. Used in basic ASCII and UNICODE modules
- st_max_size: String list maximum size. List produced by basic ASCII and UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns
- bb_max_size: BBcrack maximum size of submitted file to run module

### Result Output
1. Static Strings (ASCII, UNICODE, BASE64):
    * Tag strings matching IOC patterns of interest
    * Decoded BASE64. Extract content over 200 bytes, otherwise combine all decoded content and extract in single text file
2. Embedded PE files:
    * Extract PE files embedded in the file
    * Extract reversed PE files embedded in the file
3. ASCII Hex Strings:
    * Content extraction of ascii hex data successfully decoded (any data over 500 bytes)
    * Tag IOC pattern matching for any successfully decoded data
    * Tag URI pattern matching after custom brute force xor module (see bbcrack.py for added module)
4. BBCrack XOR Strings:
    * Tag all strings matching IOC patterns of interest
    * Extract decoded XOR'd PE File


## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name FrankenStrings \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-frankenstrings

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service FrankenStrings

Ce service effectue des extractions de fichiers et d'IOC à l'aide de la recherche de motifs, d'un décodeur d'encodage simple et de désobfuscateurs de scripts.

## Détails du service

1. Extraction de chaînes :
    * Vérification de l'IOC des chaînes ASCII et unicode. (voir patterns.py)
    * Modules de transformation XOR de Balbuzard bbcrack niveau 1 (*niveau 2 pour l'analyse en profondeur*). Correspond uniquement à des IOCs spécifiques (voir patterns.py, bbcrack.py)
    * Extraction de chaîne Base64

2. Extraction de fichiers :
    * bbcrack de Balbuzard niveau 1 (*niveau 2 pour l'analyse approfondie*) Modules de transformation XOR. (Recherche de fichiers PE uniquement)
    * Recherche du module Base64 pour les types de fichiers intéressants (voir frankenstrings.py)
    * Extraction de fichiers PE intégrés
    * Modules d'extraction Unicode, Hex, Ascii-Hex (pour un éventuel shellcode)

**Lorsqu'il n'est pas en mode d'analyse approfondie, ce service AL saute des modules de détection en fonction de la taille du fichier soumis.
(pour éviter l'engorgement du service et les dépassements de délai). Les valeurs par défaut sont
Les valeurs par défaut sont intentionnellement fixées à des tailles faibles. Les filtres peuvent être facilement modifiés dans la configuration du service,
en fonction de l'importance du trafic et du matériel utilisé par votre instance AL**.

### Configuration du service

- max_size : Taille maximale du fichier soumis pour ce service
- max_length : Longueur maximale de la chaîne. Utilisé dans les modules ASCII et UNICODE de base.
- st_max_size : Taille maximale de la liste de chaînes de caractères. Liste produite par les résultats des modules basic ASCII et UNICODE, et qui déterminera si patterns.py n'évaluera que les motifs IOC du réseau.
- bb_max_size : Taille maximale du fichier soumis à BBcrack pour l'exécution du module

### Résultat de sortie
1. Chaînes statiques (ASCII, UNICODE, BASE64) :
    * Chaînes de balises correspondant à des motifs IOC intéressants
    * BASE64 décodé. Extraire le contenu de plus de 200 octets, sinon combiner tout le contenu décodé et l'extraire dans un seul fichier texte.
2. Fichiers PE intégrés :
    * Extraire les fichiers PE intégrés dans le fichier
    * Extraction des fichiers PE inversés intégrés dans le fichier
3. Chaînes hexadécimales ASCII :
    * Extraction du contenu des données hexagonales ASCII décodées avec succès (toutes les données de plus de 500 octets).
    * Correspondance des motifs IOC des étiquettes pour toutes les données décodées avec succès
    * Correspondance des motifs URI des balises après le module xor de force brute personnalisé (voir bbcrack.py pour le module ajouté).
4. BBCrack XOR Strings :
    * Étiqueter toutes les chaînes correspondant à des motifs IOC d'intérêt
    * Extraire le fichier PE XOR décodé

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name FrankenStrings \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-frankenstrings

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
