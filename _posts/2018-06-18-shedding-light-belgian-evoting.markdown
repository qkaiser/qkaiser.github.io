---
layout: post
title:  "Shedding some light on the new Belgian eVoting system"
date:   2018-06-18 08:30:00
author: qkaiser
excerpt: |
    With the next rounds of elections approaching in Belgium (municipal elections in October 2018, federal elections in June 2019), I decided to take a look at the new system currently under development.
image: assets/martine_functional_diagram_small.png
comments: true
categories: evoting
---


With the next rounds of elections approaching in Belgium (municipal elections in October 2018, federal elections in June 2019), I decided to take a look at the new system currently under development.

Everything started from a discussion with a close friend: knowing that the source code of election software won't be availble until *after* the elections, what could an adversary get from open source intelligence gathering and a little bit of investigation ? How could that information be leveraged to disrupt the election process ?

**PSA:** none of what I'll describe below involve hacking or unauthorized access.

**PSA2:** someone (you know who you are) forced me to translate this in French, you can find the translation [here](#FR).

#### Public Competitive Tendering

My first stop was looking at draft laws and executive documents on the new electronic voting system. Since the decision to drop [the old system](/) was taken, a public competitive tendering was set up. We can see in the screenshot below (source: [http://www.dekamer.be/FLWB/PDF/54/1353/54K1353008.pdf](http://www.dekamer.be/FLWB/PDF/54/1353/54K1353008.pdf)) that the budget for this new system nicknamed "MARTINE (**Ma**nagement, **R**egistration and **T**ransmission of **In**formation and results about **E**lection)" is 420.000€.

{:.foo}
![law_screen]({{site.url}}/assets/54K1353008_screen1.png)


Looking for who won this competitive tendering, I stumbled upon this [document](http://www.ibz.rrn.fgov.be/fileadmin/user_upload/fr/rn/rapports/comite/2017/AG-20171206/AG-20171206-01-Legislation-2017-et-projets-DGIP-FR.pdf) which is a belgian Federal Service of Internal Affairs general assembly presentation from 2017. We can find the following slides in this document:

{:.foo}
![AG-20171206_screen1]({{site.url}}/assets/AG-20171206_screen1.png)

{:.foo}
![AG-20171206_screen2]({{site.url}}/assets/AG-20171206_screen2.png)


So, the company who won this public competitive tendering is **CIVADIS**. CIVADIS [acquired](https://www.civadis.be/index.php/g%C3%A9n%C3%A9ral/297-officialisation-de-la-fusion-entre-stesud-et-civadis) the [company](http://www.stesud.be/index2.php) who developped the bug-ridden system that I [analyzed back in 2014](http://quentinkaiser.be/analysis/2015/05/12/how-not-to-build-an-evoting-system/). CIVADIS itself is part of a bigger belgian ICT consultancy group named [NRB](http://www.nrb.be/).

The diagram below should help you understand components of their structure involved in this evoting project:

{:.foo}
![civadis_galaxy]({{site.url}}/assets/civadis_galaxy.png)

Note that CIVADIS takes care of vote tallying, transmission, and publication systems which will be in use for each voting method (paper and electronic). For cities in Belgium that chose to stick to electronic voting booths, the booths will be provided by [Smartmatic](http://www.smartmatic.com/).

As for auditing of this system, a city of Brussels employee told me in an email that *"To this day, both contractors chose PWC for certification and audit"*.

So pretty much keep the 2014 team and start again.


#### Finding Martine

From there I just had to do some Googling with the right set of keywords to find information about MARTINE. One of the first hit was a personal website with a [page](http://www.arnaudp.be/martine) containing the complete list of hosts and websites that are part of the MARTINE infrastructure.

**Edit:** The page is no longer accessible but can be seen via [Google webcache](http://webcache.googleusercontent.com/search?q=cache:TNmNtr2HsqkJ:  www.arnaudp.be/martine+&cd=4&hl=fr&ct=clnk&gl=be).

**Edit 2:** The webcache is dead now, so here is a screenshot I took:

{:.foo}
![arnaudp_be_martine.png]({{site.url}}/assets/arnaudp_be_martine.png)


#### Mapping Martine 

I extracted everything I could from that discovered web page (URLs, hostnames, naming conventions, ...). Everything is hosted on subdomains of [martineproject.be](www.martineproject.be), in a subnet managed by CIGER (a sub-branch of NRB). A look at Certificate Transparency logs returns interesting [results](https://crt.sh/?q=%25.martineproject.be) too. I started taking automated screenshots of them with cutycapt to see what was running there to confirm it really is election software.

{:.foo}
![martine_ma1x_screenshot]({{site.url}}/assets/martine_ma1x_screenshot.png)

After a while, and based on my initial knowledge acquired during the 2014 elections, I started mapping everything out on paper. My current understanding of the whole solution is summarized in the diagram below (you can click on it for a version with larger resolution).

{:.foo}
[![martine_functional_diagram]({{site.url}}/assets/martine_functional_diagram_small.png)]({{site.url}}/assets/martine_functional_diagram.png)


#### Understanding Martine

The following components are part of the architecture:

* **MA1B** - Introduce results, generate PDF report and sign it with polling station president eID.
* **MA2X** - Introduce results and generate "Format F" (CSV) file.
* **MA1L** - Encoding of political parties, candidates, polling stations details.
* **MA1V** - Supervision of MA1L.
* **MA3X** - Information about polling stations.
* **MA5** - Introduction of results by embassies ?
* **MA5V** - Visualisation app to monitor reception of embassies results ?
* **Collect** - Reception of results and signed PDF from MA2X/MA1L/MA5.
* **Calculate** - Reception of collected results from Collect and vote tallying.
* **Cockpits** - Monitoring and overview of the whole operation.
* **Diffuse** - Publication platform, available to press organizations on the night of the election.

**Update 26/09/2018**: my understanding of those components seems to be right based on a recently published [document](http://electionslocales.wallonie.be/sites/default/files/documents_telechargeables/Formation_MARTINE_CIVADIS.pdf).

Those who read my research from 2014 will see some similarities here. If I use the 2014 nomenclature: MA1L is Web1, MA1B is Pgm2, MA2X is Pgm3, Collect is Loc1, and Calculate is Loc2. The big difference is that instead of having thick clients running on laptop in polling stations, they chose to have polling stations presidents connect to websites to transmit results.

As for the software stack, each application seems to have been developed in Java and runs on WildFly behind Nginx acting as a reverse proxy, hosted on Linux servers. Let's just say it's a good thing they're moving away from their previous software stack which was mostly PHP web apps running on Windows with Flash applications for Cockpits.

#### Auditing Martine

If we take a look at the latest revision of the [ordonnance](https://elections2018.brussels/sites/default/files/2018-02/Ord%20vote%20%C3%A9lectronique.pdf) for electronic voting in Brussels, electronic voting software will be published once they have been audited. A more or less litteral translation of what they consider to fall into that "electronic voting software" definition is *"software provided by the government that polling stations and central polling stations need to use"*. That's ... rather vague.

{:.foo}
![ordonnance_vote_screen1]({{site.url}}/assets/ordonnance_vote_screen1.png)

[IANAL](https://www.urbandictionary.com/define.php?term=IANAL), but I think we can consider that orange components in the diagram below falls under that definition. Keep in mind that I'm not 100% sure that MA5/MA5V is software used by embassies to transmit results so its status may change in the future.

{:.foo}
[![evoting_software_overview_small]({{site.url}}/assets/evoting_software_overview_small.png)]({{site.url}}/assets/evoting_software_overview.png)

(Idea for that diagram comes from Rob van der Veer's OWASP AppSec 2015 [presentation](https://2015.appsec.eu/wp-content/uploads/2015/09/owasp-appseceu2015-vanderveer.pdf))

Based on my analysis, I think we should expect the belgian government to publish the source code of 3 web applications (MA1B, MA2X, MA5), ~~an OCR-based paper vote counting solution (DEPASS)~~, and 3 Linux virtual machines from Smartmatic (ECM, PM, VM).

**Edit (19/06/2018):** as indicated by [@DavidGlaude](https://twitter.com/DavidGlaude), DEPASS is not deployed in Brussels and the ordonnance therefore does not apply to it. I edited the diagram and my text to reflect that.

Given the large code base it represents, it would be nice that the belgian infosec community set up events similar to [DEFCON Voting Machine Hacking Vilage](https://www.wired.com/story/voting-machine-hacks-defcon/) so that people can look at it together.

#### Conclusion

This is a work in progress and I'll do my best to update this post and document the new system as I gather new information but so far I can already assert that:

* there is a lot of components involved in the election process and it can be really difficult to find them all. Hopefully having a comprehensive list of them will help us when we request access to the source code.
* the law on electronic voting is too vague. It does not define precisely what is or isn't considered to be "electronic voting software".
* the fact they use Jenkins is a good indicator they might be using a source code control system. So hopefully we won't need to dig into messy archives packaged in a hurry.
* the fact that this whole infrastructure is exposed to the public Internet is troubling. They even managed to get themselves [indexed](https://www.google.com/search?q=site%3Amartineproject.be) by Google.

If you made it this far, thanks for reading :) If you have questions, do not hesitate to contact me via Twitter/Email/Comments. I'll do my best to answer them.

<p id="FR" ></p>

## FR



Avec les élections approchant en Belgique (élections communales en octobre 2018, puis les élections fédérales en 2019), j'ai décidé de jeter un coup d'oeil au nouveau système en cours de développement...

Tout est parti d'une discussion avec un ami: sachant que le code source des logiciels électoraux ne seront publiés qu'*après* les élections, qu'est-ce qu'un adversaire pourrait obtenir grâce à un peu d'OSINT et d'investigation en ligne ? Comment ces informations pourraient-elles être utilisées pour mettre à mal le processus électoral ?

**PSA:** rien de ce que je décris ci-dessous n'a été obtenu via un accès non autorisé ou hacking de quelque sorte que ce soit.


#### Offre de Marché Public

Mon enquête commence par de la lecture. J'ai commencé par des projets de lois et des documents de l'exécutif abordant les nouvelles mesures en matière de vote électronique. Depuis que la décision d'abandonner [l'ancien système](/) a été prise, une offre de marché public a été mise en place. On peut le voir dans la capture d'écran ci-dessous (source: [http://www.dekamer.be/FLWB/PDF/54/1353/54K1353008.pdf](http://www.dekamer.be/FLWB/PDF/54/1353/54K1353008.pdf))  que le budget pour ce nouveau système baptisé "MARTINE (**Ma**nagement, **R**egistration and **T**ransmission of **In**formation and results about **E**lection)" est de 420.000€.

{:.foo}
![law_screen]({{site.url}}/assets/54K1353008_screen1.png)


En cherchant qui obtenu ce marché public, je suis tombé sur ce [document](http://www.ibz.rrn.fgov.be/fileadmin/user_upload/fr/rn/rapports/comite/2017/AG-20171206/AG-20171206-01-Legislation-2017-et-projets-DGIP-FR.pdf) provenant d'une assemblée générale du service fédéral des affaires intérieures daté de 2017. On retrouve les deux slides ci-dessous dans le document:

{:.foo}
![AG-20171206_screen1]({{site.url}}/assets/AG-20171206_screen1.png)

{:.foo}
![AG-20171206_screen2]({{site.url}}/assets/AG-20171206_screen2.png)


On y apprend que la société retenue pour l'offre de marché public est **CIVADIS**. CIVADIS a [acquis](https://www.civadis.be/index.php/g%C3%A9n%C3%A9ral/297-officialisation-de-la-fusion-entre-stesud-et-civadis) la [société](http://www.stesud.be/index2.php) qui a developpé le système que j'avais précédemment [analysé en 2014](http://quentinkaiser.be/analysis/2015/05/12/how-not-to-build-an-evoting-system/). CIVADIS fait partie d'un groupe plus large, [NRB](http://www.nrb.be/), qui est spécialisé dans la consultance en informatique.

Le diagramme ci-dessous devrait vous aider à comprendre les différents composants de sa structure qui sont impliqués dans ce projet de vote électronique:

{:.foo}
![civadis_galaxy]({{site.url}}/assets/civadis_galaxy.png)

Retenez que CIVADIS prend en charge le décompte, la totalisation, la transmission, ainsi que la publication des votes autant pour le vote papier que le vote électronique. Pour les villes belges qui ont décidé de continuer à utiliser des machines de vote électronique, celles-ci seront fournies par la société [Smartmatic](http://www.smartmatic.com/).

Quand à l'audit du système, un employé de la ville de Bruxelles m'a indiqué par mail qu' *"à ce jour, les deux sociétés ont choisi PWC pour la certification et l'audit."*.

On conserve donc la même équipe de 2014 et on recommence.


#### Finding Martine

A partir de ces informations, il me restait à faire quelques recherches Google avec les bons mots-clés pour trouver un lot d'informations sur MARTINE. L'une des premières pages référencées vient d'un [site perso](http://www.arnaudp.be/martine) contenant la liste complète des serveurs et sites web composant l'infrastructure de MARTINE.

**Edit:** La page n'est plus accessible mais peut encore être observée via [Google webcache](http://webcache.googleusercontent.com/search?q=cache:TNmNtr2HsqkJ:  www.arnaudp.be/martine+&cd=4&hl=fr&ct=clnk&gl=be).

**Edit 2:** Le web cache vient d'expirer, donc voici une capture d'écran:

{:.foo}
![arnaudp_be_martine.png]({{site.url}}/assets/arnaudp_be_martine.png)


#### Mapping Martine

Ayant extrait tout ce que je pouvais de cette page (URLs, noms de domaines, conventions de nommage, ...), je peux affirmer que tout est hébergé sur des sous-domaines de [martineproject.be](www.martineproject.be), dans un subnet géré par CIGER (une succursale de NRB). Un rapide coup d'oeil aux Certificate Transparency logs retourne quelques [résultats](https://crt.sh/?q=%25.martineproject.be) intéressants également. J'ai commencé à prendre des captures d'écrans de manière automatisée avec cutycapt pour voir si ce qui tournait sur ces sites étaient bien des logiciels électoraux.

{:.foo}
![martine_ma1x_screenshot]({{site.url}}/assets/martine_ma1x_screenshot.png)

Après quelques temps - et en me basant sur ce que j'ai appris lors des élections de 2014 - j'ai commencé par dessiner la structure telle que je la comprenais sur papier. Ma compréhension actuelle de la solution est décrite dans le diagramme ci-dessous (une version avec une meilleur résolution est disponible si vous cliquez sur l'image).

{:.foo}
[![martine_functional_diagram]({{site.url}}/assets/martine_functional_diagram_small.png)]({{site.url}}/assets/martine_functional_diagram.png)


#### Understanding Martine

Les composants ci-dessous font partie de l'infrastructure:

* **MA1B** - Introduction des résultats, génération d'un PV en PDF qui est signé par le président du bureau de vote avec son eID ?
* **MA2X** - Introduction des résulats et génération du "Format F" (CSV) ?
* **MA1L** - Encodage par les partis des listes électorales, des candidats. Encodage des bureaux de votes par le ministère.
* **MA1V** - Application de supervision de MA1L.
* **MA5** - Introduction des résultats par les ambassades ?
* **MA5V** - Application de visualisations pour monitorer la réception des résultats provenant des amabassades ?
* **Collect** - Réception des résultats et des PDF signés depuis MA2X/MA1L/MA5.
* **Calculate** - Réception des résultats récoltés par Collect et décomptage des votes.
* **Cockpits** - Monitoring et supervision de toutes les opérations.
* **Diffuse** - Plateforme de publication, disponible aux groupes de presse lors de la nuit des élections.

**Update 26/09/2018**: ma compréhension des différents composants semble être juste étant donné ce [document](http://electionslocales.wallonie.be/sites/default/files/documents_telechargeables/Formation_MARTINE_CIVADIS.pdf) de formation récement publié.

Ceux qui ont lu mes recherches de 2014 observeront certainement quelques similarités. Si l'on utilise la nomenclature de 2014: MA1L est Web1, MA1B est Pgm2, MA2X est Pgm3, Collect est Loc1, et Calculate est Loc2. La différence majeure ici, c'est qu'au lieu d'avoir un client lourd s'exécutant sur le laptop du président du bureau de vote, c'est le navigateur de ce laptop qui sera utilisé pour se connecter aux différents sites web afin d'encoder les résultats.

Quand à la couche logicielle, chaque application semble avoir été développée en Java et est exécutée par WildFly derrière un serveur Nginx agissant comme un *reverse proxy*, le tout hébergé sur des serveurs Linux. Loin sont les jours où toutes leurs applications web étaient développées en PHP/Flash et tournait sur des serveurs Windows.

#### Auditing Martine

Si l'on jette un coup d'oeil à la dernière révision de l'[ordonnance](https://elections2018.brussels/sites/default/files/2018-02/Ord%20vote%20%C3%A9lectronique.pdf) régissant le vote électronique à Bruxelles, on apprend que le code source des différents logiciels sera publié une fois qu'ils ont été agréés.

La définition de ces logiciels provient de l'alinéa §1: *"les logiciels informatiques que ceux-ci [les bureaux de votes] doivent utiliser"*. Une définition plutôt vague. En se faisant l'avocat du diable, on peut considérer que Microsoft Windows, ou encore Acrobat Reader sont des logiciels que les bureaux de vote doivent utiliser. Le code source de ces logiciels sera-t-il publié par l'Etat ?

{:.foo}
![ordonnance_vote_screen1]({{site.url}}/assets/ordonnance_vote_screen1.png)
[
IANAL](https://www.urbandictionary.com/define.php?term=IANAL), mais je pense que l'on peut considérer les composants orange dans le diagramme ci-dessous comme tombant sous cette définition. Notez que je ne suis pas encore sûr à 100% que MA5/MA5V soient les interfaces utilisées par les ambassades pour la transmission des votes.

{:.foo}
[![evoting_software_overview_small]({{site.url}}/assets/evoting_software_overview_small.png)]({{site.url}}/assets/evoting_software_overview.png)

(L'idée originale du diagramme provient de Rob van der Veer's OWASP AppSec 2015 [presentation](https://2015.appsec.eu/wp-content/uploads/2015/09/owasp-appseceu2015-vanderveer.pdf))

En se basant sur mon analyse, je pense que l'on peut attendre du gouvernement la publication du code source de 3 applications web (MA1B, MA2X, MA5), ~~d'une application OCR de dépouillement (DEPASS)~~, ainsi que 3 machines virtuelles Linux de Smartmatic (ECM, PM, VM).

**Edit (19/06/2018):** comme indiqué par [@DavidGlaude](https://twitter.com/DavidGlaude), DEPASS n'est pas déployé à Bruxelles et l'ordonnance ne s'applique donc pas à ce système. J'ai édité le diagramme pour refléter cet état de fait.

Etant donné l'ampleur du code, il serait intéressant que la communauté infosec belge mette en place un événement similaire au [DEFCON Voting Machine Hacking Vilage](https://www.wired.com/story/voting-machine-hacks-defcon/) afin que différentes personnes puissent l'analyser ensemble.

#### Conclusion

C'est un *work in progress* et je vais faire de mon mieux pour mettre à jour ce billet et documenter ce nouveau système dès que de nouvelles informations apparaissent. L'on peut déjà affirmer que:

* il y a énormément de composants impliqués dans le processus de vote électronique et il est difficile de tous les trouver. J'espère que cette analyse aidera les personnes intéressées lorsqu'elles réclameront accès aux codes sources des logiciels électoraux.
* la loi sur le vote électronique est trop vague à mon avis. Elle ne définit pas assez précisément ce qui est considéré comme "logiciel de vote électronique".
* le fait qu'ils utilisent Jenkins est un bon indicateur qu'ils utilisent un système de gestion de version. Avec un peu de chance cela permettra d'avoir des archives claires des différents logiciels.
* le fait qu'une majeure partie de l'infrastructure soit exposée sur l'Internet est troublant. Ils ont même réussi à se faire [indexer](https://www.google.com/search?q=site%3Amartineproject.be) par Google.

Si vous êtes arrivé jusqu'ici, merci de m'avoir lu :) Si vous avez des questions n'hésitez pas à me contacter via Twitter/Email/Commentaires. Je ferai de mon mieux pour répondre dans les temps.

