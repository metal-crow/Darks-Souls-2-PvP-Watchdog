Darks-Souls-2-PvP-Watchdog
==========================
  
No longer being worked on, development is dead. I dont play 2 anymore.  
Would allow people playing dark souls 2 to exclude a person they have matched up with, and not connect with them again.  
  
RESULTS:  
Well, after testing i have determined that Dark souls 2 will fall back to a dedicated server connection with valve's server if p2p fails.
See attached image for me sending Dark Souls 2 data packets direct to valve's servers, while im playing against a person http://a.pomf.se/cbmgyy.png  
  
However, this tool CAN be used to force dedicated servers, so this may help with lag.
  
Turns out Steam's NAT-punching proxies makes ip based blocking imposible, so any mesures have to be done in-game.   Infausto's tool https://bitbucket.org/infausto/dark-souls-pvp-watchdog is probably what you want to look at, especially since 1's now on steam, if you want to figure out how to block people.  
I'd say try finding where in-engine the game gets the other player's steam id when they connect, and use an in-engine kick function based on that, but good luck finding where that's stored, if its client side at all.  

HOW TO USE
==========================
Run this program by right clicking run.bat and RUNNING IT AS ADMINISTRATOR after you open Dark Souls 2.

Currently, this program can only be run on Windows, because i rely on windows firewall and cmd to get processes.


INFO
==========================
Requires the Winpcap driver for windows to be installed. http://www.winpcap.org/default.htm
Written using the jNetPcap java wrapper library.


Currently very much an alpha.
Also, i have no clue how to use jNetPcap, so this will probably look awful if you do.

