Syme
0.2.0

DESCRIPTION

Identifies users who are legitigately hitting your site. Another way to say 
it is that this projects identifies users who are not legitimate for the 
following reasons:

- spoofing User Agent
- spoofing IP Address 
- using Anonymous Proxy Servers

A unique and reproducable "fingerprint" is created for the user from both 
infomation available to the browser as well as connection information.  Other 
approaches to browser fingerprinting that are found in the Internet work from 
on the Browser or Connection perspective.  Information from these two sources 
are stored in a database for later referral.  

Tests are conducted on the user including:

- Compare timezone of browser to the timezone of the connection
- Browser IP Address determination 
- Ensure Referer header is known 

When errors occur, a Javascript alert message is shown on the page and the 
user's browser is redirected.
 
DEPENDENCIES

This package depends on:

- npm install csv 
- sudo npm install -g node-gyp (if needed) 
- npm install request 
- npm install yamlparser 
- npm install sqlite3
- npm install useragent 
- sudo npm install forever -g

RUNNING

1) Command Line

a) nohup node syme.js &

b) tail -f nohup.out

2) Daemon

a)forever -a -o ./logs/syme.log -e ./logs/syme.error start syme.js

Log files are located in ./logs with temporary logs located in the 
[HOME]/.forever directory.

b) forever stop syme.js

c) forever list 

d) forever logs syme.js

e) Turn on Write Ahead Logging in SQLite

PRAGMA journal_mode=WAL;

INSPIRATION

Syme worked at the Ministry of Truth in George Orwells's 1984.  The Party 
"vaporised" Syme for being a lucidly thinking intellectual.  He became an 
unperson who never had existed.  This package determines the truth about the 
website user and removes traces of itself in the process.
 
ACKNOWLEDGEMENTS

Carlo Zottmann - jquery browser-fingerprint plugin
Evan Tahler node.js browser_fingerprint module

