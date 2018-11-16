
# Project Telecom

Robbe Heirman, robbe.heirman@student.uantwerpen.be
Jules Desmet, jules.desmet@student.uantwerpen.be

## Tussentijdse evaluatie

Voorlopig hebben we enkel het sturen van de RSVP berichten geïmplementeerd.

## Elementen

* RSVPSource: genereert RSVP berichten mbv een handler. Er wordt ook genoeg ruimte voorzien voor UDP, IPv4 en Ethernet headers.

* De verschillende structs in RSVPStructs.hh: deze representeren de verschillende RSVP objecten etc.

## Handlers

* RSVPSource.send: genereert een RSVP pakket afhankelijk van het argument, de mogelijke argumenten zijn (hoofdletters zijn nodig):

  * Path
  * Resv
  * PathErr
  * ResvErr
  * PathTear
  * ResvTear
  * ResvConf

   Bijvoorbeeld voor een RSVPSource element 'source' kan je met "source.send Path" een RSVP path bericht genereren.
