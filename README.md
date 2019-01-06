
Project Telecom
===============


[Robbe Heirman](robbe.heirman@student.uantwerpen.be)
[Jules Desmet](jules.desmet@student.uantwerpen.be)


Bestanden
---------

De click elementen die we hebben geïmplementeerd voor dit project zijn terug te vinden in de
_elements/_ folder. De bijbehorende click scriptjes die deze elementen gebruiken hebben we in de
_scripts/_ folder geplaatst.

Om het project te compileren moeten de elementen in (een subfolder van) _~/click/elements/local/_
in de VM geplaatst worden. De _host.click_ en _router.click_ scriptjes in _~/click/scripts/routers/_
moeten vervangen worden door onze gelijknamige click scriptjes. De folder
_scripts/routers/CompoundElements/_ moet volledig in _~/click/scripts/routers/_ geplaatst worden
zodat onze host en router deze elementen kunnen gebruiken.

Verder zijn er geen bestanden die nog verplaatst moeten worden. Eens alles gecompileerd is en de
*start_click.sh* scriptjes eventueel zijn aangepast is alles klaar.

Handlers
--------

Wanneer de code is gecompileerd en click wordt gestart kan het verloop van het programma worden
beïnvloed met handlers. We hebben enkel de vier gevraagde handlers geïmplementeerd voor de host.

Om een reservatie te beginnen moet eerst en vooral een sessie worden gedefinieerd in elke host.
Dit kan met de **session ID, DST, PORT** handler. De drie argumenten zijn een ID (uniek per host),
een IPv4 adres en een UDP poort. Deze handler definieert een sessie; in de twee hosts die samen een
reservatie willen maken moeten sessies met gelijke adressen en poorten aangemaakt worden.

De host (host1) die als zender een reservatie wilt over het netwerk naar de ontvangende host (host2)
moet dan de **sender ID, SRC, PORT** handler aanroepen. De argumenten zijn van dezelfde types als
voor de **session** handler. Bij deze handler zijn het adres en de poort echter kenmerken van de
zendende node. Alleen host1 moet deze aanroepen, host2 moet dit niet doen.

Host2 moet dan weer wel de reservatie bevestigen. Wanneer deze voor een sessie een Path bericht
heeft ontvangen, dan kan de **reserve ID, CONF** handler aangeroepen worden. Het **ID** argument is
ook hier het ID nummer van de lokale sessie. **CONF** is een boolean en duidt aan of de ontvanger
een ResvConf bericht verwacht als reactie op het eerste Resv bericht. Deze handler is enkel bedoeld
voor host2 en kan alleen maar werken als de host al een Path bericht heeft ontvangen.

De laatste handler **release ID** heeft slechts één argument, het ID van de lokale sessie. Deze
handler zal ofwel een PathTear ofwel een ResvTear bericht sturen, afhankelijk van op welke host de
handler wordt gebruikt.

