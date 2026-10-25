# 🔍 HAweb-infoCK

> Outil de **reconnaissance web pour CTF**, en français, qui tourne dans le terminal.
> Tape le nom du site, choisis un bouton, ça scanne tout : hébergeur, DNS, WHOIS, pages, sous-domaines, ports, SSL…

![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)
![Windows](https://img.shields.io/badge/OS-Windows-0078D6?logo=windows&logoColor=white)
![Licence MIT](https://img.shields.io/badge/licence-MIT-green)
![Zéro dépendance](https://img.shields.io/badge/d%C3%A9pendances-z%C3%A9ro-blue)

---

## 🚀 Installation

### Option A — Exécutable Windows (le plus simple)

1. Va dans l'onglet [**Releases**](https://github.com/brikodepo/HAweb-infoCK/releases) et télécharge `HAweb-infoCK.exe`.
2. **Double-clique dessus.** Rien à installer, tout est embarqué dans le fichier.

> 🛡️ Si Windows affiche *« source inconnue »* : *Informations complémentaires → Exécuter quand même* (normal, l'exécutable est fait maison et non signé).

### Option B — Avec Node.js (Windows, Linux, macOS)

Prérequis : [Node.js 18+](https://nodejs.org/).

```bash
git clone https://github.com/brikodepo/HAweb-infoCK.git
cd HAweb-infoCK
node HAweb-infoCK.js
# ou avec une cible directe :
node HAweb-infoCK.js example.com
# audit complet non-interactif (avec export auto du rapport) :
node HAweb-infoCK.js example.com --full
```

Aucune dépendance npm à installer : le script n'utilise que des modules natifs de Node.js.

---

## 🕹️ Utilisation

Au lancement, l'outil affiche un menu à boutons :

```
  🔍 HAweb-infoCK
  Recon web CTF : hébergeur • DNS • whois • pages • sous-domaines • ports • SSL

  CIBLE : example.com

   1  🎯  Définir / changer la cible  [ espace pour marquer le nom du site ]
   2  🌐  IP + Hébergeur + Géolocalisation
   3  📡  DNS complet (A, MX, NS, TXT, SPF, DMARC)
   4  📄  WHOIS du domaine
   5  🧱  Headers HTTP + technos détectées
   6  🤖  robots.txt / sitemap.xml / security.txt
   7  🕷️   Crawler — toutes les pages du site
   8  🔍  Sous-domaines (crt.sh + bruteforce)
   9  🚪  Scan des ports communs
   10 📁  Fichiers sensibles & pages admin
   11 🔒  Certificat SSL + domaines liés
   12 💥  TOUT LANCER — audit complet
   13 💾  Exporter le rapport (.md)
   0  ❌  Quitter
```

1. Bouton **1** : entre le nom du site (ex. `challenge.ctf.fr`).
2. Choisis un bouton (**2** à **11**) pour un test ciblé, ou **12** pour l'audit complet.
3. Bouton **13** : exporte tout dans `HAweb-infoCK-<cible>-<date>.md`.

## 💡 Méthode conseillée en CTF

1. Lance **12** (audit complet) puis **13** (export du rapport).
2. Examine en priorité :
   - les `Disallow` du `robots.txt` et les URLs du `sitemap.xml` ;
   - les SANs du certificat SSL (= autres domaines = nouvelles pistes) ;
   - les sous-domaines trouvés via crt.sh ;
   - les ports ouverts inhabituels ;
   - chaque `200` du scan de fichiers sensibles (`/.git/HEAD`, `/.env`, `/admin/`…) → à ouvrir dans le navigateur.

---

## 📁 Contenu du dépôt

| Fichier            | Rôle                                                        |
|--------------------|-------------------------------------------------------------|
| `HAweb-infoCK.js`  | Le programme complet (un seul script Node.js, zéro dép.)    |
| `HAweb-infoCK.bat` | Lanceur Windows quand Node.js est installé                  |
| `package.json`     | Métadonnées npm (`npm start` fonctionne aussi)              |
| `LICENSE`          | Licence MIT                                                 |

> `HAweb-infoCK.exe` (~75 Mo : script + Node embarqué) n'est **pas** versionné ici — récupère-le dans les **Releases**.

### Reconstruire l'exécutable soi-même

```bash
mkdir build && cp HAweb-infoCK.js build/
cp "/c/Program Files/nodejs/node.exe" build/node.exe   # chemin Windows
npx --yes caxa --input build --output HAweb-infoCK.exe \
  -- "{{caxa}}/node.exe" "{{caxa}}/HAweb-infoCK.js"
```

---

## ⚠️ Avertissement

Outil conçu pour le **CTF et l'audit de systèmes dont tu as l'autorisation**.
N'utilise cet outil que sur des cibles autorisées (challenges CTF, tes propres sites, périmètres de pentest).

## 📜 Licence

[MIT](LICENSE)
