---
layout: post
title:  "How not to build an electronic voting system"
date:   2015-05-12 00:05:00
comments: true
categories: analysis
---


Depuis la mise en fonction des systèmes de vote électronique en Belgique,
chaque année d'élection a apporté son lot de problèmes techniques et de bugs à
corriger. Certains plutôt risibles, d'autres carrément inquiétants.
Grâce à une requête en transparence administrative effectuée par poureva en
1997 ayant obtenue gain de cause en
[2001](http://www.poureva.be/spip.php?article139), le Ministère de l'Intérieur
met à disposition le code source de ses applications destinées au vote
électronique.
Or, depuis cette date, aucun organisme indépendant excepté
[afront]({{site.url}}assets/afront.pdf) ne s'est lancé dans une analyse complète
de ceux-ci. Plusieurs analyses "haut niveau" ont été effectuées par poureva,
l'une abordant l'[adn du code](http://www.poureva.be/spip.php?article851),
le [threat vector](http://www.poureva.be/spip.php?article384) et le
[bug2505](http://www.poureva.be/spip.php?article853).

Cet article est une analyse non-exhaustive des systèmes de vote électronique
déployés en Belgique. Cette analyse a pour objectif de démystifier le
fonctionnement du vote électronique et de mettre en lumière les erreurs que
j'ai pu rencontrer en élaborant des scénario précis attaquant la sécurité du
système. Loin d'être un détracteur du vote électronique, j'espère que cet
article permettra de montrer à quel point la mise en place d'un système de vote
électronique sûr et stable est une tâche complexe qui doit être effectuée par
des professionnels compétents et validé sur base de critères précis.

Je commencerai par définir le concept de vote cryptographiquement sûr avant de
décrire le fonctionnement du système Digivote, de l'ouverture des bureaux de
votes à la clôture des élections. J'aborderai ensuite les trois vecteurs
d'attaques que j'ai exploré : la carte magnétique, l'encodage des votes
(en transit et au repos) ainsi que le service web de récolte des votes.
Une fois l'exploration de ces vecteurs terminée, je conclurai sur une note
positive - je l'espère - avec une liste de recommandations pour l'avenir.

Les sources analysées sont celles de Digivote (MAV v.9.16., URN v.9.15),
PGM2 v.275, PGM3 v.1.66b ainsi que Web2 v.1.0.4.
Ces sources sont disponibles sur le portail du Ministère de l'Intérieur à l'adresse
[http://www.elections.fgov.be/index.php?id=3285&L=0](http://www.elections.fgov.be/index.php?id=3285&L=0)


#### Transparence vous dites ?

Bien que le Ministère de l'Intérieur soit *obligé* par la loi de fournir les
sources des applications servant au vote électronique, il semble que les
entreprises fournissant ces applications ont une certaine définition du terme
transparence. Selon moi, la transparence d'un logiciel ne passe que par la
publication de son code source.
Pour rappel, la wikipédia défini un code source comme étant

> “un texte qui représente les instructions qui doivent être exécutées par un
microprocesseur. Le code source se matérialise souvent sous la forme d'un
ensemble de fichiers textes. Le code source est généralement écrit dans un
langage de programmation permettant ainsi une meilleure compréhension par des
humains.”

Le code des programmes Mav et Urn est rédigé en langage C et les sources sont
bien accessibles mais, celui des logiciels PGM2 et PGM3 n'est fourni que dans
un format compilé (executable Windows).
De plus, comme nous le verrons plus tard, de nombreuses composantes du système
de récolte des votes ne sont pas du tout publiée.
Mes compétences en *reverse engineering* étant relativement limitées, j'ai
focalisé mon analyse sur les logiciels **Urn**, **Mav** ainsi que sur
l'application web **Web2**.


On remarquera également cette note laissée sur le site web elections.fgov.be:

> “Le logiciel électoral n'est pas secret.
S'il n'est divulgué que le jour des élections,
c'est uniquement pour éviter toute fraude.”

Ce à quoi je laisserai Kerckoffs[[4](#4)] répondre:

> “Il faut qu'un système cryptographique n'exige pas le secret, et qu'il puisse
sans inconvénients tomber entre les mains de l'ennemi.”
>


#### Le vote cryptographiquement sûr

Afin de bien comprendre les enjeux concernant la sécurité du vote électronique,
il est nécessaire de définir le concept de vote cryptographiquement sûr.
Bien que les définitions de vote cryptographiquement sûr varie selon les auteurs,
un consensus assez clair vis-à-vis de ses caractéristiques ressortent des articles
de l'Internet Policy Institute [[1](#1)], Karlof et al.[[2](#2)] ainsi que
d'Olaniyi et al.[[3](#3)].

J'en ai retenu douze, dont vous pouvez retrouver les définitions ci-dessous:

**Confidentialité** Tous les votes restent secrets alors que le vote a lieu et
chaque vote individuel ne peut être lié par un individu à l'électeur qui l'a
effectué.

**Non-répudiation** Le mécanisme permettant de prouver qui est l'émetteur du
message.

**Authentification / Démocracie** Seuls les électeurs autorisés sont admis au
vote.

**Exactitude** Chaque urne doit être correctement recomptée dans total,
certains auteurs définissant une marge d'erreur tolérable.

**Intégrité** Il ne doit pas être possible de modifier, forger ou supprimer un
vote.

**Non-coertion** Chaque vote reste secret lors du processus d'élection.
Les électeurs ne peuvent pas être en mesure de prouver pour qui ils ont voté à
une personne tierce afin de réduire le risque de coertion et d'activité
d'achats de votes.

**Unicité** Chaque électeur a le même nombre de voix. Aucun électeur ne peut
être en mesure de voter plus de fois que les autres.

**Traçabilité** Le système doit pouvoir proposer un système de traçabilité
permettant de vérifier que chaque vote a été compté correctement dans le total
afin de maintenir la sécurité du système.

**Transparence** Le processus des élections doit être transparent pour
l'électeur. Les électeurs doivent pouvoir comprendre le mécanisme du système
de vote électronique afin de savoir si leur vote a effectivement bien été pris
en compte.

**Simplicité** Le système doit être facile d'utilisation pour tous les citoyens.
Il doit, par exemple, remplir les besoins des PMR, analphabète et mal-voyant.

**Equité** Aucuns résultats partiels ne peuvent être disponibles avant que le
résultat final soit publié.

**Vérifiabilité** Le système de vote doit être vérifié afin d'être certain
qu'il remplisse les critère nécessaires.


On remarquera que ces caractéristiques sont fortement liées aux principes même
du vote démocratique. À la différence ici qu'ils devront être renforcés et
assurés par la technologie déployée.

#### Vue d'ensemble

Chaque électeur reçoit une
[carte magnétique](http://en.wikipedia.org/wiki/Magnetic_stripe_card)
initialisée par un assesseur grâce à la machine exécutant le programme Urn.
L'initialisation de la carte inscrit le token de l'élection en cours, le type
d'électeur (N pour national, E pour européen, S pour étranger) ainsi qu'un vote
blanc avec son HMAC respectif.

Une fois que l'électeur a reçu sa carte, il peut rejoindre l'isoloir ou la
machine exécutant le programmer Mav lui permet de voter et d'inscrire ce vote
sur la carte magnétique. Le programme Mav vérifie que le token de la carte est
valide avant d'autoriser la personne à voter.

Une fois le vote inscrit sur la carte magnétique, l'électeur peut retourner vers
la machine exécutant le programme Urn afin que celle-ci lise son vote et
l'inscrive dans un fichier. La carte est ensuite avalée dans une boite scellée.

## Accès Autorisé


Tout d'abord, les disquettes et des mots de passe de président sont générées
dans un lieu central et *sécurisé* (garde, caméra). Le président reçoit
par courrier le mot de passe sous la forme d'un ticket à gratter et ce,
quelques jours avant la date des élections. Les disquettes, elles, sont dans une
enveloppe scellée qui l'attend à son bureau de vote. Le président doit
normalement attendre que son bureau soit constitué (prestation de serment des
assesseurs et témoins) avant d'ouvrir cette enveloppe.

Là, il démarre et initialise la première machine *Urn*. Les disquettes
(en double exemplaire) ne sont pas protégées en écriture et passe de machine en
machine. Evidemment, impossible de savoir ce qu'il y avait dessus et les coups
de sonde des experts sont inopérants. Surtout que la fonction de vérification
d'intégrité de la disquette était [erroné](#bonus) de 1994 à 2012.

Si le président oublie sa lettre avec le mot de passe, pas de problème, la commune
possède tous les mots de passe. Et on peut toujours appeler le Ministère de l'Intérieur
qui les fourni et a aussi tous les mots de passe.

Ce mot de passe est composé de 10 caractères numériques.
Il n'est pas comparé à une valeur prédéfinie, mais le programme
vérifie la validité de celui-ci grâce au calcul d'une somme de contrôle.
Ce système de validation de mot de passe n'est, a priori, pas problèmatique, car
la valeur du mot de passe est ensuite utilisée pour dériver une clé secrète.
Si la clé obtenue n'est pas la bonne, le programme ne fonctionnera pas.

Le calcul de la somme de contrôle est décrit ci-dessous et est quasi identique
à celui utilisé pour votre numéro de registre national si vous êtes un citoyen
belge.

![Mot de passe de présidents de bureau de vote - Somme de controle.]({{site.url}}/assets/password.png)

{% highlight c %}

#define integrityModulus 97
#define integrityOffset 99
reference = integrityOffset - (fullPasswordValue % integrityModulus);
return (extension!=reference)
{% endhighlight %}

## Cartes à collectionner

Comme on l'a vu précédemment, le système Digivote repose sur l'utilisation de
cartes magnétiques. Il me semblait donc normal de m'attaquer à cet aspect du
système pour voir s'il était possible de lire un vote, de le modifier voir de
créer des cartes *escroc*.
En effet, ce type d'attaque permettrait de prouver que la majorité des
caractéristiques du vote cryptographiquement sûr ne sont pas respectées par le
processus de vote mis en place avec Digivote.

J'introduirai tout d'abord la carte magnétique et la manière dont les données
du vote sont stockée dessus avant de démontrer les différents types d'attaques
et les erreurs commises qui les rendent possibles.

### Carte Magnétique - Schéma


![card layout]({{site.url}}assets/card_layout.png)

**Token [5 bytes]** Le token est une chaine de 5 caractères destinée à
identifier de manière unique le bureau de vote où la carte à été initialisée.

**Passage [1 byte]** Une valeur binaire indiquant si un vote a déjà été encodé
sur la carte.

**MAC [4 byte]** La représentation hexadécimale du Message Authentication Code
du vote. Il permet de vérifier que le vote n'a pas été altéré et qu'il a bien
été écrit par un système de confiance.

**Test [1 byte]** Un caractère indiquant le type de votant (`N` pour belge,
`E` pour européen et `S` pour étranger)

**Vote [2 + x bytes]** Deux caractères indiquant le numéro de la liste pour
laquelle le vote a été effectué ainsi qu'un nombre de caractères variable
correspondant à la représentation hexadécimale du tableau contenant les votes
de préférences pour la liste choisie (ex. [1,0,1,1,0,0,1,1] devient A2).


### Carte Magnétique - Vulnérabilités

J'ai retenu trois types d'attaques envers la carte magnétique :

* lire le contenu de la carte magnétique
* modifier le contenu de la carte magnétique
* créer une carte *escroc*

#### Lire le contenu de la carte

Les données étant inscrites *en clair* sur la carte magnétique, il est très
simple d'obtenir le vote inscrit sur celle-ci.
On peut prendre deux positions vis-à-vis de cette situation. Soit on
considère que l'on calque le modèle papier, soit on considère qu'il est
nécessaire de respecter les conditions du vote cryptographiquement sûr.

Si l'on se calque sur le modèle papier, il est normal de stocker les données en
clair (comme l'est votre vote inscrit au crayon sur papier) car personne ne va
pouvoir vous arrêter entre l'isoloir et l'urne pour lire votre carte ou votre
bulletin de vote sans qu'un assesseur n'intervienne.

#### Modifier le contenu de la carte magnétique

En inspectant les données stockées sur la carte magnétique, la modification
d'une valeur sans être détecté peut permettre plusieurs choses :

* la modification arbitraire du contenu du token, du passage, du MAC ou du vote
permet de rendre une carte invalide
* la modification du byte de test par une valeur autre que `N`, `E`, `S`
permet de rendre une carte invalide
* la modification du byte de test vers une valeur acceptée  (`N`, `E` et `S`)
permet d'augmenter ou de limiter les capacités de vote d'un électeur en lui
permettant de voter ou non pour certains types d'élections en cours.

#### Créer une carte escroc

Bien qu'il soit aisé de lire le contenu d'un vote inscrit sur une carte ou de
la rendre invalide par une modification arbitraire de son contenu, la
possibilité de forger des cartes valides semble cependant compromise au vu de
la validation effectuée par le programme Urn.

Cette validation repose sur trois éléments:

- le nombre de bytes contenus sur la carte
- la valeur du token
- la valeur du MAC

### Carte Magnétique - Escrocs

Pour qu'un attaquant puisse forger une carte magnétique, il lui est donc
nécessaire de connaitre le nombre de bytes contenu dans une carte valide,
la valeur du token mais également la manière dont est calculé le MAC du vote.

#### Obtention du nombre de bytes

Obtenir le nombre de bytes stockés sur la carte est trivial et peut même
s'effectuer sans lecture préalable d'une carte. En effet, sachant comment les
votes de préférences sont stockés sur la carte (cfr. Carte Magnétique - Schéma)
il suffit d'obtenir le nombre maximum de candidat pour chaque élection en cours
afin d'obtenir le nombre total de bytes stockés.

#### Obtention du token

La valeur du token est inscrite sur la carte afin que l'urne puisse vérifier
que la carte a effectivement été initialisée dans le même bureau de vote.

![token generation]({{site.url}}assets/token_generation.png)

Le calcul du token inscrit sur la carte magnétique se fait en trois étapes :

1. Un *token étendu* est lu depuis le fichier ```machvots.tbl```.
Ce token contient le numéro de canton, le numéro secondaire et principal du
bureau de vote ainsi que la date du vote au formatt jj mm aa.

2. Une valeur *hard codée*, présente sur les machines de vote et dans les urnes,
contient la valeur ```0EC3ZN678LAB2DFRH1IJK9M5OPQGSTUVWXY4```. Cette valeur
est utilisée pour générer le token de la carte.

3. Le token de la carte est généré en allant chercher des valeurs dans
   ```code``` à des index dépendants des valeurs du token étendu.

{% highlight C %}
void Calcul_Jeton(char *Jeton_Etendu, char *Jeton)
{
    int jj, mm,aa;
    int cant,buv1,buv2,tmp;
    char Cjj[3],Cmm[3],Caa[3];
    char Ccant[4], Cbuv1[4],Cbuv2[4];

    strncpy(Ccant,Jeton_Etendu + 3,3);
    strncpy(Cbuv1,Jeton_Etendu  + 6,2);
    strncpy(Cbuv2,Jeton_Etendu  + 8,1);
    strncpy(Cjj,Jeton_Etendu   + 9,2);
    strncpy(Cmm,Jeton_Etendu  + 11,2);
    strncpy(Caa,Jeton_Etendu  + 13,2);

    Ccant[3] = '\0';
    Cbuv1[2] = '\0';
    Cbuv2[1] = '\0';
    Cjj[2]   = '\0';
    Cmm[2]   = '\0';
    Caa[2]   = '\0';

    cant     = atoi(Ccant);
    buv1     = atoi(Cbuv1);
    buv2     = atoi(Cbuv2);
    jj       = atoi(Cjj);
    mm       = atoi(Cmm);
    aa       = atoi(Caa);


    Jeton[1] = _Code[buv1 % 35];
    Jeton[3] = _Code[buv2 % 35];
    Jeton[2] = _Code[(jj + cant) % 35];
    Jeton[0] = _Code[mm   % 35];
    Jeton[4] = _Code[aa   % 35];

    Jeton[5] = '\0';
}
{% endhighlight %}

Sachant que la valeur de `code` n'a pas changé pour les différentes élections,
il existe deux possibilités pour obtenir ce token :

- lire une carte magnétique de l'élection courante et en extraire le token
- lire sa convocation électorale pour obtenir le numéro primaire et secondaire
du bureau de vote ainsi que la date de l'élection afin de générer le token

#### Calcul du MAC

Un code d'authentification de message (MAC, Message Authentication Code) est un
code accompagnant des données dans le but d'assurer l'intégrité de ces dernières
en permettant de vérifier qu'elles n'ont subi aucune modification,
après une transmission par exemple. Le MAC assure non seulement une fonction
de vérification de l'intégrité du message, mais il permet également d'authentifier
l’expéditeur, détenteur de la clé secrète ayant servi au calcul de cette
valeur.

L'algorithme utilisé par Digivote est défini par [ISO/IEC
9797-1](https://en.wikipedia.org/wiki/ISO/IEC_9797-1) (algorithme 2,
padding 2). Les données sur lesquelles sont appliquées le calcul du MAC sont
composées du byte de test ainsi que des bytes du vote.

La fonction utilisée est `Calcul_Crc` représentée ici :

{% highlight c %}
void Calcul_Crc(char *Carte, int pos)
{
 int i,j;
 char Ca[3], Cai[3], Buff[70];

 Ca[0] = 0x80;
 Ca[1] = 0x80;
 Ca[2] = 0x00;

 for (i = 0; i < giVoteMaxBytes + _C_TEST_MAX_BYTE;
       Buff[i] = Carte[pos + i], i++);

 Buff[giVoteMaxBytes + _C_TEST_MAX_BYTE] = 0x00;

 computeMac (macResult, macResultLen, Buff, giVoteMaxBytes + _C_TEST_MAX_BYTE, decryptedMacKeyMini);
 for(i = 0,j = 4; i < 4;i++,j++)
 {
   Ca[0] = Ca[0] ^ (unsigned char) macResult[i];
   Ca[1] = Ca[1] ^ (unsigned char) macResult[j];
 }
   sprintf(Cai, "%02X",(unsigned char) Ca[0]);
   strcpy(gszCrcCalcul,Cai);
   sprintf(Cai, "%02X",(unsigned char) Ca[1]);
   strcat(gszCrcCalcul,Cai);
}
{% endhighlight %}

L'algorithme étant connu, toute la difficulté réside donc dans l'obtention de
la clé utilisée pour calculer le MAC de la carte.

Cette clé est obtenue de la manière suivante : 

{% highlight c %}
#ifdef EL2014
#define MINI_PWD "6987"
#define MINI_POS "2368"
#endif

#ifdef EL2014
char Minicodage[] = MINI_PWD;
#else
char Minicodage[] = "6870";
#endif
// ...
extern char gszMinipassword[12];
//...
#ifdef EL2014
CMinipassword[0] = fullPassword[MINI_POS[0]-49];  //it's 50 - 49 (1)
CMinipassword[1] = fullPassword[MINI_POS[1]-49];  //it's 51 - 49 (2) 
CMinipassword[2] = fullPassword[MINI_POS[2]-49];  //it's 54 - 49 (5)
CMinipassword[3] = fullPassword[MINI_POS[3]-49];  //it's 56 - 49 (7) 
#else
CMinipassword[0] = fullPassword[0];
CMinipassword[1] = fullPassword[1];
CMinipassword[2] = fullPassword[3];
CMinipassword[3] = fullPassword[7];
#endif
gszMinipassword[4] = 0x00;
strcat(gszMinipassword,Minicodage);
//...
extendPassword(fullPasswordMini,gszMinipassword);
//...
computeKeyFromPassword (decryptedMacKeyMini, fullPasswordMini);
{% endhighlight %}

La variable `fullPassword` contient le mot de passe de 10 caractères numériques
encodé par le président de bureau. La fonction `extendPassword`, calcule la
valeur de l'extension comme on l'a vu précédemment.

![password key derivation]({{site.url}}assets/pkd.png)

La clé est donc dérivée depuis un mot de passe de 10 caractères dont nous
connaissons 6 caractères. En effet, la variable de `Minicodage` est connue et
contient 4 caractères tandis que nous connaissons l'algorithme
(`extendPassword`) permettant d'obtenir les deux derniers caractères du mot de
passe. Il ne peut donc exister que 10⁴ valeurs possibles pour ce mot de passe.

En possession d'une carte magnétique, il nous est possible de lire la valeur
du vote ainsi que la valeur du MAC. Connaissant ces valeurs, il nous est
possible d'utiliser une attaque par *brute force* afin d'obtenir la clé secrète
comme suit :

* énumérer les 10⁴ combinaisons possibles de mot de passe
* dériver la clé pour chaque mot de passe obtenu
* calculer le MAC du vote lu depuis la carte avec chaque clé dérivée
* si, pour une clé dérivée, le MAC correspond à celui inscrit sur la carte, 
nous avons trouvé la clé

#### Résultats

Muni de la clé secrète et de la valeur du token, il nous est possible de créer
des cartes *escroc* totalement valide pour le programme Urn. 

De plus, en trouvant la clé, nous avons également trouvé 4 caractères du mot de
passe du président de bureau de vote. Nous connaissons donc 6 caractères sur 10
(4 caractère trouvé + 2 caractère de l'extension) du mot de passe du président
destiné à l'initialisation des machines.

## Secure Storage

Une fois qu'un électeur a inscrit sont vote grâce à une machine exécutant le
programme Mav, il peut insérer sa carte dans une des urnes électroniques.
Les urnes électroniques exécutent le programme Urn qui valide le contenu de la
carte, encode le vote dans un fichier et stocke enfin la carte dans l'urne
physique.

Concernant le stockage des votes en mémoire, j'ai exploré deux possibilités :

* est-il possible de manipuler le contenu des votes ?
* est-il possible de lier un vote à un électeur ?


Tant que l'élection est en cours, tous les votes sont encodés de manière
chiffrée dans un fichier temporaire. Lorsque le président de bureau clôture le
vote, le contenu de ce fichier temporaire est chiffré avec 
[AES](https://fr.wikipedia.org/wiki/Advanced_Encryption_Standard) et inscrit
dans un nouveau fichier. Le fichier temporaire étant ensuite supprimé.

Une fois le contenu chiffré sur les disquettes, le président emmène celles-ci
vers le bureau de totalisation avec le secrétaire de son choix. Ce qui est
l'équivalent de se déplacer avec une urne non scellée. Il a en fait tout le
logiciel pour fabriquer le résultat qui lui plait. Normalement, les disquettes
devraient être dans des enveloppes scellées, mais ce n'est pas la pratique.

Le logiciel de totalisation demande au président d'encoder son mot de passe,
lit le contenu des disquettes et produit un résultat qui est imprimé
localement.

### Manipuler le contenu du fichier temporaire

Voici comment les votes sont encodés dans le fichier temporaire : 

{% highlight c %}
void Encrypt_Decrypt(char *pzInputData, char *pzPassword, unsigned int iSize)
{
    unsigned int i, iKeySize;
    iKeySize = strlen(pzPassword);

    for (i= 0; i < iSize; i++)
    {
	pzInputData[i] ^=  pzPassword[i % iKeySize];
    }
    pzInputData[iSize] = 0x00;
}
{% endhighlight %}

Le chiffrement appliqué sur le contenu du vote est donc un *XOR cipher* qui se base sur la valeur de `pzPassword` comme clé. La valeur de `pzPassword` est obtenue avec la fonction suivante : 

{% highlight c %}
void Generate_Password(char *pzPassword, long Position, boolean bIndic)
{
	long E_Position;
	char szPos[8];

	//compute the position in the file
	if(bIndic)
	{
		E_Position = (long)_E_TABLE;
		E_Position +=(long)((long)((long)C_VOTE_MAX_BYTE + 5L) * (long)Position);
	}
	else
		E_Position = Position;

	sprintf(szPos,"%07ld",E_Position);
	if(szPos[0] == '-')
		szPos[0] = '0';

	pzPassword[0] = CMinipassword[0];
	pzPassword[1] = szPos[3];
	pzPassword[2] = CMinipassword[2];
	pzPassword[3] = szPos[4];
	pzPassword[4] = CMinipassword[7];
	pzPassword[5] = szPos[5];
	pzPassword[6] = CMinipassword[4];
	pzPassword[7] = szPos[6];
	pzPassword[8] = szPos[0];
	pzPassword[9] = CMinipassword[1];
	pzPassword[10] = CMinipassword[3];
	pzPassword[11] = szPos[2];
	pzPassword[12] = CMinipassword[6];
	pzPassword[13] = szPos[1];
	pzPassword[14] = CMinipassword[5];
    pzPassword[15] = 0x00;
}
{% endhighlight %}

Le mot de passe est donc composé de la position du vote dans le fichier mais
également de la valeur de CMinipassword.

La valeur de CMinipassword est obtenue comme suit:

{% highlight c %}
#ifdef EL2014
#define MINI_PWD "6987"
#define MINI_POS "2368"
#endif

#ifdef EL2014
char Minicodage[] = MINI_PWD;
#else
char Minicodage[] = "6870";
#endif

// [...]

#ifdef EL2014
CMinipassword[0] = fullPassword[MINI_POS[0]-49];  //it's 50 - 49 (1)
CMinipassword[1] = fullPassword[MINI_POS[1]-49];  //it's 51 - 49 (2) 
CMinipassword[2] = fullPassword[MINI_POS[2]-49];  //it's 54 - 49 (5)
CMinipassword[3] = fullPassword[MINI_POS[3]-49];  //it's 56 - 49 (7) 
#else
CMinipassword[0] = fullPassword[0];
CMinipassword[1] = fullPassword[1];
CMinipassword[2] = fullPassword[3];
CMinipassword[3] = fullPassword[7];
#endif
CMinipassword[4] = 0x00;
strcat(CMinipassword,Minicodage);
{% endhighlight %}

Le filtre du *XOR cipher* est donc composé de 7 bytes provenant de la position
du vote dans le fichier, de 4 bytes contenant la valeur de Minicodage et de
4 bytes du mot de passe administrateur.
Connaissant la position et la valeur de Minicodage, nous avons deux possibilités
à notre disposition pour obtenir les 4 bytes restant du filtre : 

* effectuer une attaque par *brute force* en énumérant les 10⁴ possibilités,
en supposant qu'il soit possible de déterminer si le contenu déchiffré est
valide ou non
* étant donné que les 4 bytes manquant correspondent aux 4 bytes obtenus par
*brute force* dans l'attaque sur la carte magnétique, il nous suffit d'utiliser
cette attaque pour obtenir les 4 bytes manquant.


Connaissant la clé utilisée pour le  *XOR cipher* il nous est possible d'ajouter
et de modifier le contenu des votes inscrits dans le fichier temporaire.

### Déchiffrer le contenu du fichier

Le contenu du fichier temporaire est, à la fermeture des bureaux, inscrit dans
un nouveau fichier qui est ensuite chiffré avec AES.
À première vue, déchiffrer le contenu du fichier semble donc impossible.
Malheureusement, les développeurs ont fait les erreurs suivantes :

* l'*initialization vector* est stocké dans le fichier ```floppy.be```
* la clé secrète est stockée dans le fichier ```floppy.be```
* ```floppy.be``` se situe sur la même disquette que celle où est
stocké le fichier chiffré

Le contenu du fichier ```floppy.be``` est lui-même chiffré avec AES.
Il est donc nécessaire de connaitre la clé secrète ayant chiffré le contenu de
```floppy.be``` afin d'obtenir la clé permettant de déchiffrer le fichier
contenant les votes.

Cette clé, c'est la clé obtenue en dérivant le mot de passe administrateur.

Comme on le sait, il est possible de récupérer 6 caractères sur 10 du mot de
passe administrateur grâce à une carte magnétique. Il serait donc possible
d'énumérer les 10⁴ combinaisons possibles pour les 4 caractères manquants,
de dériver chaque combinaison et d'appliquer le processus de déchiffrement avec chacune des clés
obtenues.

Le format des lignes du fichier étant connu, il me parait plus
que probable de pouvoir vérifier que le contenu déchiffré correspond au format
(par exemple, en vérifiant que le type de votant de chaque ligne est bien `N`,
`S` ou `E`). S'il est possible d'effectuer cette validation, nous aurons non
seulement récupéré tous les votes contenus dans le fichier mais également le
mot de passe administrateur du président de bureau de vote.


Le schéma ci-dessous décrit de manière très brouillonne comment les différentes
clés et IV sont obtenues.

![aes stupid]({{site.url}}assets/aes_attack.png)

### Bonus

<div id="bonus"></div>
Le code de vérification d'intégrité a été corrigé en 2014 et jamais détecté
auparavant.

{% highlight c %}
#ifdef EL2014                                                                   
    for (i = 0; i < macResultLen;i++)
      if(macResult[i] != wrkspc[i+16])
        return(0);                                                              
    return(1);
#else                                                                           
    for (i = 0; i < macResultLen;i++)
      if(macResult[i] != wrkspc[i+16])
        return(0);                                                              
      else
        return(1);                                                              
    return(0);
#endif 
{% endhighlight %}

## Infrastructure

Lorsque j'ai débuté mon analyse, j'ai toujours été persuadé qu'aborder
l'infrastructure d'envoi et de récolte des votes aurait été un exercice
difficile et entièrement basé sur la supposition.

Heureusement, Stesud a fourni la documentation technique
complète de cette infrastructure (cartographie réseau, description des
services et systèmes). Le fichier, comme on peut le constater ici, était
relativement bien enterré dans l'archive mise à disposition.

<pre style="background-color:#111;color:white;font-family:'monospace';">
$ cd /tmp
$ wget http://www.elections.fgov.be/fileadmin/user_upload/\
Elections2014/FR/Electeurs/en_pratique/soft/codi.zip
$ unzip codi.zip
$ cd Codi
$ cd PGM2\ -\ 275/
$ unzip PgmRef.zip
$ cd ZCOCKPIT
$ unzip t15M
$ libreoffice doctechnique01150842.doc
</pre>

On peut décemment supposer que la présence de ce fichier est une erreur
malencontreuse de la part de Stesud. Cependant, aucune modification de
l'archive n'a été effectuée par Stesud ou l'IBZ depuis septembre 2014, date à
laquelle je les ai notifiés vis-à-vis de cette fuite d'information.

Je décris de manière assez simple l'infrastructure réseau mise en place dans
les prochaines sections, pour plus de détails vous pouvez retrouver toute
l'information sur le [wiki](http://sandbox.quentinkaiser.be/wiki).

### Transmission Sécurisée

Une fois le contenu des votes chiffrés et inscrit sur la disquette, cette
disquette est transmise au bureau de canton afin que son contenu soit déchiffré
et intégré aux résultats du canton avec le logiciel PGM2.
Une fois tous les résultats lus et encodés, le logiciel génère un fichier pdf
contenant un récapitulatif des résultats.
Ce fichier pdf est signé par le président de bureau grâce à sa carte d'identité
électronique.

Ce fichier pdf est ensuite transmis via PGM3 vers l'infrastructure de l'IBZ
et/ou de Stésud. Je tiens à signaler que le fonctionnement de PGM2 et PGM3
n'est que pure spéculation, basée sur le contenu des guides d'utilisation mis
à disposition par Stésud.

#### Services

* Les programmes Pgm ont été dévéloppés avec Centura et sont utilisés sur les
PCs des bureaux principaux.

    * Pgm1 : bureau de circonscription et collège : introduction et validation des listes
    * Pgm2 : bureau principaux : introductions des résultats, calcul et génération du procès-verbal
    * Pgm3 : bureau de cantons électroniques : introduction des résultats et génération du procès-verbal
    * Pgm5 : comparaison de 2 fichiers résultats au format F


* Les programmes Web sont des applications développées en php (la plupart avec Zend), s'exécutant sur les serveurs du SPF Intérieur.

    * Web1 : encodage des listes par les partis, des bureaux de votes par les communes, consultations des coordonnées des bureaux de cantons.
    * Web2 : enregistrement des résultats par les ambassades étrangères
    * Web3 : intranet interne au SPF Intérieur avec les résultats des élections
    * Web4 : cockpit pour le suivi et la supervision des opérations
    * Web5 : serveur web de publication des résultats pour le grand public

* Les programmes Loc ont été dévéloppé avec Centura et s'exécutent sur les serveurs du SPF Intérieur.

    * Loc1 : réception des fichiers provenant des bureaux principaux et transfert à loc 2
    * Loc2 : vérification des fichiers reçus de loc 2, chargement en base de données, calcul et transfert des résultats vers loc 3, consultation des données enregistrées dans la base de données de loc 2.
    * Loc3 : transfert des résultats vers les différents partenaires.


### Réseau

Comme on peut le remarquer sur les cartes réseau ci-dessous, les clients
peuvent accéder aux serveurs à la fois via le réseau Internet et à la fois via
le réseau Publilink.

Pour information, Publilink c'est ça:

> PubliLink est conçu sur un réseau privé totalement verrouillé en gestion chez
> Belgacom auquel diverses administrations publiques, Belfius Banque et tous
> les autres fournisseurs de services sont affiliés.[<a href="#7">7</a>,<a href="#8">8</a>]

On peut décemment se poser les questions suivantes vis-à-vis de cette cartographie:

* Pourquoi offrir la possibilité aux clients PGM1 et PGM2 de se connecter à
  l'infrastructure de récolte des votes via Internet alors que Publilink semble
être une solution bien plus sûre et sécurisée ?

* Pourquoi l'infrastructure de backup est-elle hébergée chez un fournisseur
  privé ?

* Quelles garanties vis-à-vis de la sécurité du réseau l'IBZ et Stésud peuvent
  fournir ? Le réseau a-t-il été audité ?

![networking]({{site.url}}assets/codi3.png)
![networking2]({{site.url}}assets/codi4.png)

## Web Application (In)Security

Après avoir remonté la chaine jusqu'à l'infrastructure du SPF Intérieur, nous
allons dès maintenant jeter un coup d'oeil aux applications qui permettent à
l'entiereté du processus électoral de prendre place.
En effet, ces applications web réceptionnent, calculent et redistribuent les
résultats des votes pour tous les électeurs belges.
Que vous ayez voté sur papier ou de manière électronique, votre vote a été
comptabilisé via ces applications.

Tout d'abord, il faut savoir que seules les sources de Web2 sont disponibles
sur le portail du Ministère de l'Intérieur. Cela signifie que sept applications
sur les huit utilisées dans la réception, le calcul et la diffusion des votes ne
sont pas fournies aux citoyens alors qu'ils prennent une part tout aussi
importante dans le processus électoral.

Les applications WebX sont développées en php avec le framework Zend tandis que
les applications LocX sont des exécutables windows développés de la même manière
que les logiciels PGM2/PGM3 (GuptaSql).

#### Accès

Si vous jetez un coup d'oeil au fichier createUsers.php dans config/DB, vous
aurez le plaisir de rencontrer ceci :

{% highlight php %}
<?php
// User creation
$usersAdmin = array(
		array("usr"=>"ADMINCODI", "psw"=> "84322640"),
		array("usr"=>"DIRGEN", "psw"=> "38165024")
);
?>
{% endhighlight %}

Il était toujours possible d'accéder l'interface de Web2 avec ces comptes
administrateurs après les élections du 25/05/2014. Ces accès ont été
désactivés le 05/09/2014 suite à une notification de ma part auprès de Stesud.

#### Clé privée pas si privée

Si vous allez dans le répertoire ```library/encrypt/cert``` vous aurez le
plaisir de croiser deux clés privées et deux certificats.
Le challenge password des deux clés privées est dans le fichier `run.bat` stocké
dans ```library/encrypt```.

**codiSender.pem**

<pre style="background-color:#222;color:white;font-family:'monospace';">
quentin@localhost:~/Codi/Web2/v1.0.4/library/encrypt/cert$ openssl rsa -in codiSender.pem
Enter pass phrase for codiSender.pem:
writing RSA key
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCeRdpC5RkV97ViOJeMru6rWqV+NTZkOFafizn9LulLC0R56umN
zN/3K9OuXHLkrB3IJzUkiXKD6pt9i/wQEDl5LhJ2omhR7rgSUeCPe4wigXk3YdFW
kj8MZyzWKPNLOaU0QCcAkBLS/51/HaogpVwCpCvNkKLXPQIDOUijwCiCZQIDAQAB
AoGANCIIIa6605yTN3YynRll7jVee7LlZp+UENtYT4grOhfNB2eUZKvOPelGwZEc
GyyCZtJbU9yeRst5SiJY9aWSeE4991GegjEvg84dB5EVPQQYzpLRkMfOP5WoHNlD
+TM+yvAOeAJ7pZUnmD4vMmMjKiBrf/IfRaqS1tWFl4KdvKECQQDQvLCvxllDyhJg
1qzyYx0UR5DWJOMTvrc9dU/9ITp4Bi/n1SVYFV2S36B4J95CBUMeDymt6ViC9Iqz
S0gZKeVJAkEAwhwJelA9zymRTTVpQ7FNs/6EvXS+DBXesVoLqdAFKuGyqX1dvUP1
qIthm6MN9Jrc8GiOnXcrksgRMRYMTSXgPQJAFrznNk6R/LtvYxMfhcvcKBBfq6Qb
BFSbG1vDGdzbxKVP5J4oUj8JkW1AyrX1FRYDqKuYK7SmiqVe0ocZ1Hvm2QJBALMC
lj8FtyrQw953Tl+OKQHAzHvIKOgOVzQpva3aWJmmUVT7d7Ju9SN9fwPASMN2+iB/
3F4do8KW3TvugGO5dWUCQFB7ceIDCMl2+adEPL361z8ojD096S4ZgJOqmDZTjc0v
UKk9+dop7bh1G59mddhwbKIGq7x57PzQVkv8OgkOlng=
-----END RSA PRIVATE KEY-----
</pre>

**codiSender.crt**

{% highlight text %}
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 7 (0x7)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=be, ST=luxembourg, L=marche, O=stesud, OU=elections, CN=Stesud Certificate Authority
        Validity
            Not Before: Jan 22 09:58:00 2014 GMT
            Not After : Jan 22 09:58:00 2019 GMT
        Subject: C=be, ST=luxembourg, L=marche, O=stesud, OU=elections, CN=codiSender
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (1024 bit)
                Modulus:
                    00:9e:45:da:42:e5:19:15:f7:b5:62:38:97:8c:ae:
                    ee:ab:5a:a5:7e:35:36:64:38:56:9f:8b:39:fd:2e:
                    e9:4b:0b:44:79:ea:e9:8d:cc:df:f7:2b:d3:ae:5c:
                    72:e4:ac:1d:c8:27:35:24:89:72:83:ea:9b:7d:8b:
                    fc:10:10:39:79:2e:12:76:a2:68:51:ee:b8:12:51:
                    e0:8f:7b:8c:22:81:79:37:61:d1:56:92:3f:0c:67:
                    2c:d6:28:f3:4b:39:a5:34:40:27:00:90:12:d2:ff:
                    9d:7f:1d:aa:20:a5:5c:02:a4:2b:cd:90:a2:d7:3d:
                    02:03:39:48:a3:c0:28:82:65
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                97:8F:BB:F3:67:47:13:BB:64:7A:8F:1B:D2:93:3E:BA:DB:E8:BA:06
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment, Data Encipherment
            Netscape Cert Type: 
                SSL Client, S/MIME
            Netscape Comment: 
                xca certificate
    Signature Algorithm: sha1WithRSAEncryption
         15:de:bb:5f:c6:9c:8f:f8:e2:bf:a2:e6:c9:59:69:b8:21:28:
         83:bf:67:0c:dd:02:54:c9:57:63:36:86:ad:6c:2a:f0:56:8f:
         a8:44:e3:e2:cb:73:dc:3c:89:c7:3b:41:c2:af:ff:06:73:08:
         23:68:bf:4a:dc:77:5c:e1:44:34:bf:18:ec:2e:64:b8:95:42:
         64:97:b3:81:13:db:10:3e:23:32:9f:99:f5:59:25:9a:36:64:
         6b:80:c5:6c:f3:bf:e8:ee:da:6d:f8:01:a3:c8:17:90:8a:0b:
         d4:0c:4b:b8:8b:cc:ea:b5:7f:11:fc:ea:cf:79:6d:83:59:fb:
         3c:60
{% endhighlight %}

**run.bat**

{% highlight bat %}
set action= -?

set action= -decrypt -in data.zip.crypted -out data.zip.crypted.decrypted
-rcert cert/codiReceiver.crt -rkey cert/codiReceiver.pem -rpass codi2014bystesud

echo Action is [%action%]

TestCODISecurityDll.exe %action%
{% endhighlight %}

Comme on peut le voir ces clés privées ainsi que leur certificat étaient
destinées au déchiffrement des votes reçus sous la forme d'une archive.

#### Mots de passe en clair

Lorsque l'administrateur génère les comptes utilisateurs, leurs noms ainsi que
le mot de passe correspondant sont inscrits en clair dans un fichier csv.

{% highlight php %}
<?php
$sqlInsertUsers = "INSERT INTO users VALUES (NULL,'".$userid."',
SHA1(CONCAT('".$password."','".$salt."')),'".$salt."','1','1')";
$usercontent .= $userid.";".$password."\n";
//[...]
if($usercontent != ""){
    $filename = "../../".$config->elecdata->params->filepath."wpgm2_users.csv";
    $fd=fopen($filename,"w+");
    fwrite($fd,$usercontent);
    fclose($fd);
echo "<br/>Users/password file has been generated to ".$filename."<br/>";
}
?>
{% endhighlight %}


#### Arbitrary File Inclusion

Le script disponible à l'adresse [http://codi1web.rrn.fgov.be/transweb/download.php](http://codi1web.rrn.fgov.be/transweb/download.php)
ne nécessitait aucune authentification et permettait d'obtenir n'importe quel fichier
stocké sur le serveur pour peu que le processus ai le droit en lecture dessus.

{% highlight php %}
<?php

$filename = $_GET['file'];

// required for IE, otherwise Content-disposition is ignored
if(ini_get('zlib.output_compression'))
  ini_set('zlib.output_compression', 'Off');

// addition by Jorg Weske
$file_extension = strtolower(substr(strrchr($filename,"."),1));

if( $filename == "" ) 
{
  echo "<html><title>eLouai's Download Script</title><body>ERROR: download file
NOT SPECIFIED. USE force-download.php?file=filepath</body></html>";
  exit;
} elseif ( ! file_exists( $filename ) ) 
{
  echo "<html><title>eLouai's Download Script</title><body>ERROR: File not
found. USE force-download.php?file=filepath</body></html>";
  exit;
};
switch( $file_extension )
{
  case "pdf": $ctype="application/pdf"; break;
  case "exe": $ctype="application/octet-stream"; break;
  case "zip": $ctype="application/zip"; break;
  case "doc": $ctype="application/msword"; break;
  case "xls": $ctype="application/vnd.ms-excel"; break;
  case "ppt": $ctype="application/vnd.ms-powerpoint"; break;
  case "gif": $ctype="image/gif"; break;
  case "png": $ctype="image/png"; break;
  case "jpeg":
  case "jpg": $ctype="image/jpg"; break;
  default: $ctype="application/force-download";
}
header("Pragma: public"); // required
header("Expires: 0");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
header("Cache-Control: private",false); // required for certain browsers 
header("Content-Type: $ctype");
// change, added quotes to allow spaces in filenames, by Rajkumar Singh
header("Content-Disposition: attachment; filename=\"".basename($filename)."\";"
);
header("Content-Transfer-Encoding: binary");
header("Content-Length: ".filesize($filename));
readfile("$filename");
exit();

?>
{% endhighlight %}

Une recherche sur les auteurs du script m'a permis de retrouvé le fichier
[ici](http://elouai.com/force-download.php). La seule modification ayant été
effectuée concernait le message d'erreur.

#### Disclosure timeline

- 07/2014: premier contact par mail pour indiquer la présence des comptes
- 07/2014: second contact pour la présence des clés privés
- 08/2014: relance vis-à-vis des comptes et des clés
- 09/2014: relance vis-à-vis des comptes, des clés et du local file inclusion sur deux autres mails + notification de l'IBZ
- 02/09/2014: réponse de Civadis
- 03/09/2014: Civadis minimise l'impact
- 05/09/2014: Civadis désactive les comptes
- 10/09/2014: Civadis coupe l'accès aux serveurs


## Un futur pour le vote électronique ?

Premier constat: le système Jite/Digivote n'apporte aucune nouvelle garantie
par rapport au vote papier. Il est possible de créer des cartes magnétiques
*escrocs* afin de faire du bourrage d'urne ou de l'achat de vote et il est
également possible de manipuler les votes lorsqu'ils sont stockés localement.

Deuxième constat: de nombreuses zones d'ombres persistent. D'abord, vis-à-vis
des programmes engagés dans la récolte et la gestion des votes dont le code
n'est pas publiquement disponible. Ensuite, concernant le réseau censé gérer la
récolte des votes. Quid de sa résilience, de sa solidité et de sa sécurité ?

Le plus inquiétant dans toute cette enquête, c'est que la société Stésud a mis
à disposition le même code pendant plusieurs élections, sans sourciller.
Comment une entreprise a pu, en toute conscience, s’engager dans un milieu aussi
critique que les élections libres et démocratiques avec un niveau d’expertise
aussi bas ? Mais surtout, qui va continuer à croire au
[bug des rayons cosmiques](http://www.poureva.be/spip.php?article36) ?

Un système de vote électronique, lorsqu'il est bien conçu et correctement
implémenté, est un outil efficace pour répondre aux défis que présente
l'organisation d'élections démocratiques. Malheureusement, le manque de
contrôle, de moyen et d'expertise du Ministère de l'Intérieur l'ont conduit à
renouveler ce système bien au-delà de ses limites. Renouvellement qui,
finalement, mènera à une totale perte de confiance de la population envers ces
systèmes.

Le vote papier, finalement, c'est quand même pas si mal.


## Crédits

Texte et illustrations par Quentin Kaiser sous licence [CC-By BE](http://creativecommons.org/licenses/by/2.0/be/).


## Références

<div id="1"> [1] Internet Policy Institute. Voting systems design criteria. <i>Report of the National Workshop on Internet Voting: Issues and Research Agenda</i>. USA, March 2001.</div>

<div id="2"> [2] C. Karlof, N. Sastry, D. Wagner. Cryptographic Voting Protocols: A Systems Perspective.
<i>14th USENIX Security Symposium</i>. University of California, Berkeley</div>

<div id="3"> [3] Olayemi Mikail Olaniyi, Adeoye Oludotun, Oladiran Tayo Arulogun
and Elijah Olusayo Omidior. Design of Secure Electronic Voting System Using Multifactor Authentication and Cryptographic Hash Functions.
<i>International Journal of Computer and Information Technology</i>, November 2013, Volume 02 – Issue 06</div>

<div id="4"> [4] Kerckoffs Auguste - "La cryptographie militaire" - <i>Journal des sciences militaires</i> vol. IX, 1883, p.5-38.</div>

<div id="5"> [5] "Code d'Authentification de Message". <i>Wikipedia</i>. http://fr.wikipedia.org/wiki/Code_d%27authentification_de_message </div>

<div id="6"> [6] "Open Source". <i>Wikipedia</i>. http://fr.wikipedia.org/wiki/Open_source </div>

<div id="7"> [7] Proximus. "Publilink Explore". http://www.proximus.be/en/id_cl_publilink/companies-and-government/products-and-services/internet-and-networks/proximus-explore/publilink-explore.html</div>

<div id="8"> [8] Belfius Banque. "PubliLink : le portail et le réseau de et pour les administrations publiques". https://www.belfius.be/publicsocial/FR/ProduitsServices/ITLine/OutilsTransactionnels/Publilink/index.aspx?firstWA=no</div>

[jekyll-gh]: https://github.com/jekyll/jekyll
[jekyll]:    http://jekyllrb.com
