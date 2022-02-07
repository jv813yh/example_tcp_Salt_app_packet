##################################################
## Diplomova  praca                             ##
## Meno studenta: Jozef Vendel                  ##
## Veduci DP: prof. Ing. Milos Drutarovsky CSc. ##
## Skola: KEMT FEI TUKE                         ##
## Datum vytvorenia: 21.12.2021	                ##
##################################################

Zoznam suborov
  
 example_tcp_Salt_app
      |__INC
      |__SRC_LIB
      |__client.bat
      |__client00.c
      |__makefile
      |__read_me
      |__server.bat
      |__server00.c


Program je kompilovatelny pomocou makefile suboru a su pridane
.bat subory pre jednoduche spustenie aplikacie servera a klienta.
Server vyuziva loopback adresu a pocuva na porte 8080.
Poskytuje funkciu toupper(), ktora prevadza male znaky prijate klientom
na velke znaky a odosiela ich klientovi, kde klient prijate data vypisuje
do CLI. Zlozka INC obsahuje vsetky potrebne hlavickove subory pre pracu a 
zlozka SRC_LIB vsetky zdrojove kody, ktore aplikacia vyuziva.

Aplikacia demonstruje, pracu a nasadenie salt-channel protokolu  
na nezabezpeceny komunikacny kanal TCP (vid. zlozka example_tcp
na ktoru bol nasadeny protokol salt-channel, coho je vysledkom tato zlozka -
example_tcp_Salt_app). Protokol poskytuje na aplikacnej vrstve pracu s dvoma
typmi paketov, v tejto zlozke sa pracuje s typom AppPaket. Maximalna prenasana
velkost dat v aplikacii zavisi od konstanty MAX_SIZE, ktora je definovana
priamo v zdrojovych kodoch client00.c a server00.c
Blizsi opis paketov, aplikacie, protokolu a vsetko co s protokolom suvisi 
som opisal v diplomovej praci - "Bezpecna komunikacia s vyuzitim 
salt-channel protokolu".




