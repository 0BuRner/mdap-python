# MDAP-Python

MDAP-Python is a library written in Python to communicate with the Alcatel/Speedtouch/Thomson/Technicolor routers via the MDAP (Multi-Directory Access Protocol) protocol.

## Getting Started

### Prerequisites

There is not prerequisites as this tool uses only standard libraries.

It should work with Python 2.7 =< on Windows and Unix systems.

## Usage

There is 3 ways to use this library. From command line, interactive shell or by using API.
If you run the script without arguments from command line, it will start in interactive shell mode.

Depending on the logging level, you will see more or less info when using it.

### Interactive shell

##### MDAP shell
```
mdap > help
mdap > set interface "iface ip"         // Set interface to send and listen on (for Windows users only)
mdap > discover                         // Send ANT-SEARCH packet
mdap > print                            // Display data about discovered ants
mdap > set target "ip"|"ant-id"         // Set target used by info/exec/shell commands
mdap > info [user] [password]           // Send INFO packet to target 
mdap > exec [command] [user] [password] // Send EXEC-CLI packet to target to execute command
mdap > shell [user] [password]          // Open shell-like mode to remote device 
```

##### Device shell
```
Administrator@192.168.1.1: help         // Depend on the device (same as telnet available commands)
```

### Command line arguments

Automatic discovery mode to detect your target (not working yet)

```
mdap-python.py -i 192.168.1.6 -t 192.168.1.1|ANTID1337 -m info|exec -c command -u username -p password
```

### Programming API

```python
mdap = MDAP('192.168.1.6')
mdap.discover()
mdap.set_target('192.168.1.1')
mdap.info('admin', '')
mdap.exec('user list', 'admin', '')
```

## Technical implementation

#### Classes

- MDAP_Ant : structure that contains all information about discovered/called devices 
- MDAP_Sender : create a sending socket, prepare and send data according to MDAP protocol
- MDAP_Listener : create a listening daemon socket to receive all MDAP data
- MDAP_Analyzer : analyze MDAP data received by listener and call sender to reply back if necessary 
- MDAP : entry point which initializes and links all objects

#### Threading

1. Main thread that send new UDP packet and analyze received ones from listener thread 
2. Daemon listener thread closing when main thread close. No info lost as it's in a separate thread and gives the ability to passive listening.

Because of the daemon thread, there is some timeout waiting for devices response to keep a easy to read prompt shell (useful only when debug level >= INFO). 

> **Warning** : as there is multi-threads which aren't synchronized,
> you could see incoming data before or after you send a command or even if you didn't send one

### Tested devices

- Speedtouch ST706WL
- Technicolor TG589

## MDAP Protocol

> **Disclaimer**: information about MDAP protocol is written from scratch with what I discovered when writing this library.
> It may be wrong or inaccurate. Feel free to update this README file.

MDAP is a UDP stateless protocol. It lies in the "Application Layer" regarding the OSI model.
It was registered on 2002-02-01 by Johan Deleu at Alcatel to the IANA (Internet Assigned Numbers Authority).

> **Warning**: all requests __and__ responses messages are multicasted !
> Since all messages are unencrypted (even login and password) it means all data are visible through the entire LAN.

- IP: 224.0.0.103
- PORT: 3235

It seems IP 239.255.255.0 and PORT 65000 are also used for MDAP/1.0

##### Versions

- MDAP/1.0
- MDAP/1.1
- MDAP/1.2

I have no idea about the differences between those versions.

### Goal

MDAP protocol gives the ability to detect devices on a network without knowing theirs IPs.

> **Dobrica Pavlinušić**: It's very cool idea, since you can connect as many devices as you have network ports or bandwidth, and allthough they all will boot with same IP address (and this create conflicts on IP network), you can still sand commands to each individual device using multicast.

It can also retrieve system info from a device and execute commands as in a telnet session.

### Commands

##### Requests

- ANT-SEARCH :
- INFO : 
- EXEC-CLI :
    
##### Responses

- REPLY-ANT-SEARCH : contains metadata about devices (list some of them)
- REPLY-INFO : (SEQ-NR)
- REPLY-EXEC-CLI : (SEQ-NR)

### Resources

There isn't much documentation about MDAP protocol on the internet.
Here are the few resources I found :

- http://blog.rot13.org/2007/11/cwmp-and-mdap-servers.html (November 2007)
- http://cvs.rot13.org/cgi-bin/viewvc.cgi/mdap/ - Source code in Perl and Bash of MDAP protocol implementation (November 2007)
- [http://bazaar.launchpad.net/lorenzodes/mdaphelper/head/src/mdapcast/mdapcast.c](http://bazaar.launchpad.net/~lorenzodes/+junk/mdaphelper/view/head:/src/mdapcast/mdapcast.c) - Source code in C of MDAP protocol implementation (March 2016)
- http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml#multicast-addresses-1 - Official IPv4 Multicast Address Space Registry (Up-to-date)

## Authors

* **Laurent Meirlaen** - [0BuRner](https://github.com/0BuRner) - *Initial work*

See also the list of [contributors](https://github.com/0BuRner/mdap-python/contributors) who participated in this project.

## License

This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details
