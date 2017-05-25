# Webview Netflow Reporter




## Using Webview Netflow Reporter

1. Install the docker container on a computer 
This is a Docker container. The following commands are useful:

```
cd <folder-containing-wvnr>

# build the container
docker build -t wvnr_img . 

# run the container, listening on external ports 83 for http and 22055 for netflow records
# Connect your web browser to http://localhost:83/webview
docker run -d -p 83:80 -p 22055:2055/udp --name wvnr_img wvnr_img

# 'ssh' into the container so you can look around
docker exec -i -t wvnr_img /bin/bash

# When you're done (or want to modify the Dockerfile)...
# This removes the name 'wvnr_img' for re-use with next docker run...
docker rm -f wvnr_img
```
# Overview - Webview Netflow Reporter

A lightweight Netflow collector and web display based on wvnetflow and flow-tools in a Docker container. Webview Netflow Reporter was creaated by Craig Weinhold craig.weinhold@cdw.com. 


This container listens on ports 2055 for netflow. 
It displays the collected data in a web interface.
This screenshot shows off the varying data sent through a router.
![wvnetflow screen shot](https://github.com/richb-hanover/wvnetflow)
For more information and screenshots, see [wvnetflow](http://wvnetflow.sourceforge.net/) hosted at [SourceForge.net](SourceForge.net)


*Testing Status: This container has been tested with 
Docker Community Edition Version 17.03.1-ce-mac5 (16048) 
running on a mid-2011 Mac mini, OSX 10.12.4, 
with a 2.3 GHz Intel Core i5 processor and 8 GBytes RAM. 
It works great with my LEDE/OpenWrt router after installing the softflowd package to export netflow info to nfsen/nfdump.
If you try it out, please file an issue and let me know how it worked for you.* A dockerized container to run Webview Netflow Reporter by Craig Weinhold craig.weinhold@cdw.com
This is based on flow-tools. 
For more information, see: http://wvnetflow.sourceforge.net/

This is a Docker container. The following commands are useful:

````
cd <folder-containing-wvnr>

# build the container
docker build -t wvnr_img . 

# run the container, listening on external ports 83 for http and 22055 for netflow records
# Connect your web browser to http://localhost:83/webview
docker run -d -p 83:80 -p 22055:2055/udp --name wvnr_img wvnr_img

# 'ssh' into the container so you can look around
docker exec -i -t wvnr_img /bin/bash

# When you're done (or want to modify the Dockerfile)...
# This removes the name 'wvnr_img' for re-use with next docker run...
docker rm -f wvnr_img
````

### QuickStart - Install and Test Webview Netflow Reporter

1. Install [Docker](https://www.docker.com/community-edition) (the Community Edition works fine) on a computer that's always running. nfsen/nsdump will run there and collect the netflow data 24x7.

1. Clone the *wvnetflow-dockerized* repo to that computer.
 
    ```
    $ git clone https://github.com/richb-hanover/wvnetflow-dockerized.git
    ``` 
2. Build the container from the Dockerfile

    ```
    $ cd nfsen-dockerized
    $ docker build -t nfsen-dockerized .
    ```
3. Run the container. 

    ```
  $ docker run -p 81:80 -p 2055:2055/udp -p 4739:4739/udp -p 6343:6343/udp -p 9996:9996/udp  -i -t --name nfsen_img nfsen-dockerized
    ```
4. You should see `supervisord` start the apache daemon in the terminal like so:

    ```
   2015-02-22 04:12:27,903 INFO success: apache2 entered RUNNING state, process has stayed up for > than 1 seconds (startsecs) 
    ```

5. Point your web browser to [http://localhost:81](http://localhost:81/) The browser will display a warning about "no live data." (**Note:** The `docker run...` command above maps external port 81 to the docker container's web port 80.)
6. Select *zone1_profile* from the **Profile:** (in the header dropdown)

7. Configure your router(s) to export flows to this collector, or generate mock flow data (see below). See the Flow_Export.md document for more information.

8. **Wait...** It can take up to five minutes before the flow data has been collected and displayed. After that, refreshing the browser shows the data collected at the right edge of any of the plots.

### QuickStart - Other setup information and tests

* To connect to the container via a terminal, use this command:

    ```
    $ docker exec -i -t nfsen_img /bin/bash
    ```
* Add "-d" to daemonize the container when you run it (e.g., `docker run -d -p ...`) This allows you to continue working in the same terminal window. 

* To make a change to the container, stop it with the command below (this removes the "nfsen_img" name), edit the Dockerfile, then rebuild and `docker run`...

    ```
    $ docker rm -f nfsen_img
    ```
* You can break the `run` command over multiple lines for better readability: see `docker run --help` for an explanation of the fields:

    ```
  $ docker run 
    -p 81:80 \
    -p 2055:2055/udp \
    -p 4739:4739/udp \
    -p 6343:6343/udp \
    -p 9996:9996/udp \
    -i -t --name nfsen_img \
    nfsen-dockerized
    ```
* The container opens these ports:

  * Apache default port `EXPOSE 80`
  * NetFlow default port `EXPOSE 2055`
  * IPFIX default port `EXPOSE 4739`
  * sFlow default port `EXPOSE 6343`
  * nfsen src ip src node mappings `EXPOSE 9996`


Verify the port bindings with `docker port image_name`

   ```
   $ docker port nfsen_img
  2055/udp -> 0.0.0.0:2055
  4739/udp -> 0.0.0.0:4739
  6343/udp -> 0.0.0.0:6343
  9996/udp -> 0.0.0.0:9996
  80/tcp -> 0.0.0.0:81
   ```

### QuickStart - www access

In the list should be the Apache port if no other process was already bound to the port and now point your browser at the container like so (*Note* there will not be any flows in the RRD graphs until we generate some in the next section):

    http://192.168.59.103/nfsen/nfsen.php  # use your computer's IP address

Change the dropdown box from `live` to `zone1_profile` to view live graphing of data in the profile that is packaged as part of the Docker image.

![1-empty-flow-tables](https://cloud.githubusercontent.com/assets/1711674/6328202/f8227492-bb32-11e4-9c1c-2cef151b15d0.jpg)

If you chose to map Apache web server to another port (e.g. `-p 81:80`) then add the port to the URL:

    http://192.168.59.103:81/nfsen/nfsen.php    # or port 81, if it has been remapped


### QuickStart - generate and view mock flows

There is a Go based netflow generated hacked together for this project since there were not any readily available that were simple to strictly spray data at a collector for testing. Will link to source code soon as it is cleaned up and pushed to a repo.

Note: The flow generator will at some point support choosing what protos and other parameters, but for now it just generates a handful of protocols and the same src/dst netflow payload addresses. As a result some of the protocol filters will be empty in the included protocol filters as seen in the following following screenshots.

Run the generator against the localhost with the following **(fyi, the flow generator is compiled for a Mac, will add a Linux binary shortly)**:

  $ flow-generator  -t 127.0.0.1 -p 9995

This will begin sending flow data at the collector listening on 2205/UDP (netflow). The flows are processed every 5 minutes, after 10 minutes or so you should begin seeing flows appearing in your graphs based on the pre-populated filters.

![2-graph-flow-table-empty](https://cloud.githubusercontent.com/assets/1711674/6328203/f825bb16-bb32-11e4-9294-9547bbfce1be.jpg)

From there you can drill down further into the predefined filters that are added as part of this container build in the `start.sh` runtime script included with the Dockerfile. Below the graphs are raw fdump queries against the collected nfcapd data in the following sceenshot. This is all customized in the Dockerfile and frankly the reason Docker containers are amazing for being able to distribute and convey the exact experience you desire to the consumer of your image:

![3-drilldown-flow-table](https://cloud.githubusercontent.com/assets/1711674/6328201/f81e0fec-bb32-11e4-8fcf-254ca8ddd880.jpg)


The rest of the README goes into details around exporting data sets from the network datapath and adding your own protocols and filters to create the profiles that solve problems in your environment.

Use ctrl^c to break out of the image. That will stop the image. You can start the container whenever you like with `docker start <image_name or container_id`

For more information, read [Flow_Export.md](./Flow_export.md)

### Add more ports or custom configurations and zones ###

Out of the box this container has three ports listening for NetFlow, sFlow and IPFIX

  -IPFIX   = 4739
  -sFlow   = 6343
  -NetFlow = 2055

These are configured using sed in the Dockerfile.

  %sources = (
      'netflow-global'  => { 'port' => '9995', 'col' => '#0000ff', 'type' => 'netflow' },
      'sflow-global'  => { 'port' => '6343', 'col' => '#0000ff', 'type' => 'sflow' },
      'ipfix-global'  => { 'port' => '4739', 'col' => '#0000ff', 'type' => 'netflow' },
      'peer1'        => { 'port' => '9996', 'IP' => '172.16.17.18' },
      'peer2'        => { 'port' => '9996', 'IP' => '172.16.17.19' },
  );


If you modify a running instance, simply run 'nfsen reconfig' or stop/start the service.

  $ nfsen reconfig
  New sources to configure : ipfix-global
  Continue? [y/n] y
  Add source 'ipfix-global'
  Start/restart collector on port '4739' for (ipfix-global)[8079]
  Restart nfsend:[7974]


### Generate Some Traffic ###

You can bind an ip address to the bridge for a quick way to test exports with the following. You simply move the IP from your eth0 interface to the bridge (br0 / br0, etc) interface. Drop the following into a file, give it a chmod +x with the appropriate addresses to migrate your IP from eth0 iface to OVS br0 in the case you don't have a virtual port with something attached to generate the traffic.

  ifconfig eth0 0
  sudo ovs-vsctl add-port br0 eth0
  ifconfig br0 172.16.86.134 netmask 255.255.255.0
  route add default gw 172.16.86.2 br0

After about 20 minutes or so, traffic will begin appearing. You can brute force some traffic generation from the datapath quite simply using something like Mausezahn. *Disclaimer:* Traffic generation to any other target then localhost can quickly be viewed as a denial of service depending on how scrutinized the environment you are in. To be safe, avoid prod networks, crash your home net instead.

  $ apt-get install mz
  # Careful here, its blasting randomly created crappy headers and payload all over that IP prefix. Maybe a good thing tho.
  $ mz eth0 -A rand -B 192.168.1.0/24 -c 0 -t tcp "dp=1-1024, flags=syn"  -P "star wars > star trek"

I also included a net flow generator app I wrote to export test netflow traffic to a target collector. The binary is located in the container /data/ directory and the source code is on Github. If you run that on the container it will populate the netflow graphs by default.

  $ flow-generator  -t 127.0.0.1 -p 2205

It is soft linked to bin directory but also located in /data directory

### Add more protocol filters to your graphs

The pre-built filters are a combination of well known popular ports along with the top vulnerable ports as defined by the ISC [Internet Storm Center](https://isc.sans.edu/reports.html). It is simple to add more via the client for testing or persistently add to the image by including (or replace with a new one) the new filters in the start.sh startup script called at the end of the Dockerfile. `CMD bash -C '/data/start.sh';'bash`

  Pre-built protocol filters. Add more to the definition by including them below
  nfsen --add-profile zone1_profile
  nfsen --add-channel zone1_profile/icmp filter='proto icmp' colour='#48C6FF'
  nfsen --add-channel zone1_profile/chargen filter='port 19' colour='#ED62FF'
  nfsen --add-channel zone1_profile/ftp filter='port 21' colour='#63EA7D'
  nfsen --add-channel zone1_profile/ssh filter='port 22' colour='#FF9930'
  nfsen --add-channel zone1_profile/telnet filter='port 23' colour='#4FFF10'
  nfsen --add-channel zone1_profile/dns filter='port 53' colour='#305FFF'
  nfsen --add-channel zone1_profile/http filter='port 80' colour='#AEFF20'
  nfsen --add-channel zone1_profile/dns filter='port 110' colour='#BFFFFF'
  nfsen --add-channel zone1_profile/ntp filter='port 123' colour='#FF6530'
  nfsen --add-channel zone1_profile/loc-srv filter='port 135' colour='#6267FF'
  nfsen --add-channel zone1_profile/netbios-ns filter='port 137' colour='#FF8662'
  nfsen --add-channel zone1_profile/snmp filter='port 161' colour='#77FF62'
  nfsen --add-channel zone1_profile/https filter='port 443' colour='#A787FF'
  nfsen --add-channel zone1_profile/microsoft-ds filter='port 445' colour='#F0DE65'
  nfsen --add-channel zone1_profile/http-alt filter='port 8080' colour='#209EFF'
  nfsen --add-channel zone1_profile/ms-sql-s filter='port 1433' colour='#FF6CAC'
  nfsen --add-channel zone1_profile/mysql filter='port 3306' colour='#FFFD6C'
  nfsen --add-channel zone1_profile/rdp filter='port 3389' colour='#FFFD6C'
  nfsen --add-channel zone1_profile/sip filter='port 5060' colour='#FFD962'
  nfsen --add-channel zone1_profile/p2p filter='port 6681' colour='#369EFF'
  nfsen --add-channel zone1_profile/bittorrent filter='port 6682' colour='#FF62A0'
  nfsen --commit-profile zone1_profile


**Note** you can set the time to back date the processing of graphs if  desired:

  $ nfsen --add-profile zone1_profile tstart="201502102135"

Linux network service to well-known port mappings can be found in `/etc/services`

Next you can add more channels by simply defining them using the CLI or in the 'stats' tab of the webUI or via the the nfsen client. `nfsen --add-profile` is only nessecary when initialize a profile. Modifications just use the following:

  $ nfsen --add-channel zone1_profile/<insert service name> filter='port <insert_port>' colour='<insert some fancy color>'

When you add a new channel, you will see an error as follows, you can ignore this as it just means there isnt an associated nfdump file until it is processed in the next couple of minutes as data accumaltes and the 5 minute timer to generate the rrd graphs expires.

  ERR Channel info file missing for channel

Finally you can view the profile with a *-l*:

  $ nfsen -l  zone1_profile

Example output looks as follows:

  # #
  name  zone1_profile
  group (nogroup)
  tcreate Wed Feb 11 00:10:55 2015
  tstart  Tue Feb 10 21:35:00 2015
  tend  Wed Feb 11 23:15:00 2015
  updated Wed Feb 11 23:15:00 2015
  expire  0 hours
  size  150.0 MB
  maxsize 0
  type  continuous
  locked  0
  status  OK
  version 130
  channel icmp  sign: + colour: #CF6CFF order: 1  sourcelist: zone1 Files: 310  Size: 1269760
  channel ssh sign: + colour: #FFDB6C order: 2  sourcelist: zone1 Files: 310  Size: 18243584
  channel telnet  sign: + colour: #EAA563 order: 3  sourcelist: zone1 Files: 310  Size: 1269760
  channel dns sign: + colour: #FE816B order: 4  sourcelist: zone1 Files: 310  Size: 19144704
  channel http  sign: + colour: #C0EE64 order: 5  sourcelist: zone1 Files: 310  Size: 21553152
  channel ntp sign: + colour: #6BFEF3 order: 6  sourcelist: zone1 Files: 310  Size: 2670592
  channel https sign: + colour: #64BCEE order: 7  sourcelist: zone1 Files: 310  Size: 55230464
  channel http-alt  sign: + colour: #6381EA order: 8  sourcelist: zone1 Files: 310  Size: 19288064
  channel imaps sign: + colour: #916CFF order: 9  sourcelist: zone1 Files: 264  Size: 18690048
  channel ms-sql-s  sign: + colour: #FF6CAC order: 10 sourcelist: zone1 Files: 2  Size: 8192
  channel ftp sign: + colour: #63EA7D order: 11 sourcelist: zone1 Files: 1  Size: 4096


### Modifying the Docker Image ###

  ENV COLLECTOR_IP=192.168.59.103
  ENV COLLECTOR_PORT=9995
  ENV AGENT_IP=eth0
  ENV HEADER_BYTES=512
  ENV SAMPLING_RATE=64
  ENV POLLING_SECS=5

Then cd into the directory with the Dockerfile and build the new image w/ the new options with any image name you want. The following example is (xflow_debian:v2):

    $ docker build -t xflow_debian:v2 .

And then run the new image, for example:

    $ docker run  -p 80:80 -p 9995:9995/udp -p 9996:9996/udp -i -t xflow_debian:v2

  $  docker run  -p 22 -p 81:80 -p 2055:2055/udp -p 4739:4739/udp -p 6343:6343/udp -p 9996:9996/udp  -i -t -name nfsen_img nfsen-v2.0

You can also modify the startup bash script located in /data/

In the Dockerfile find the following line:

    ADD ./start.sh /data/start.sh

The Docker build looks in the Dockerfile context on the host machine for the specified script *(./start.sh)* and places the file in the container file structure at *(/data/start.sh)*.

  ADD "host machine file/directory", "container absolute path/destination name

Simply modify the start.sh or add whatever else you want. The Dockerfile will only execute one CMD at the end of the Dockerfile, in this projects Dockerfile we run start.sh followed by `bash` which drops you into a Bash shell for further configuration or troubleshooting. RUN is the other means of configuring the container that can be used as many times as you like. Just remember the path is absolute, and WORKDIR is your friend to make it clear where you are in the order of operations and making the Dockerfile readable.

  CMD bash -C '/data/start.sh';'bash'

Docker also caches builds so you don't have to rebuild the entire thing everytime (which is amazing). Sometimes you may want to expire that cache because something outside of the Docker context has changed.

  docker build -t nflow_debian --no-cache .

*More on Dockerfile at: [Dockerfile Reference](https://docs.docker.com/reference/builder/)*


### Troubleshooting

Verify that the nfsen and nfdump processes are running:

  root@2964d8693fa4:/# nfsen status
  NfSen version: -1
  NfSen status:
  Collector for (netflow-global) port 2055 is running [31].
  Collector for (sflow-global) port 6343 is running [25].
  Collector for (ipfix-global) port 4739 is running [28].
  Collector for (peer1 peer2) port 9996 is running [22].
  nfsen daemon:  pid: [33] is running.

Check that all of the processes are running inside of the container:

  root@aba11747ca4c:/# ps -eaf | grep nf

  netflow     20     1  0 05:57 ?        00:00:00 /usr/local/bin/sfcapd -w -D -p 6343 -u netflow -g www-data -B 200000 -S 1 -P /data/nfsen/var/run/p6343.pid -z -I sflow-global -l /data/nfsen/profiles-data/live/sflow-global
  netflow     23     1  0 05:57 ?        00:00:00 /usr/local/bin/nfcapd -w -D -p 2055 -u netflow -g www-data -B 200000 -S 1 -P /data/nfsen/var/run/p2055.pid -z -I netflow-global -l /data/nfsen/profiles-data/live/netflow-global
  netflow     26     1  0 05:57 ?        00:00:00 /usr/local/bin/nfcapd -w -D -p 9996 -u netflow -g www-data -B 200000 -S 1 -P /data/nfsen/var/run/p9996.pid -z -n peer1 172.16.17.18 /data/nfsen/profiles-data/live/peer1 -n peer2 172.16.17.19 /data/nfsen/profiles-data/live/peer2
  netflow     29     1  0 05:57 ?        00:00:00 /usr/local/bin/nfcapd -w -D -p 4739 -u netflow -g www-data -B 200000 -S 1 -P /data/nfsen/var/run/p4739.pid -z -I ipfix-global -l /data/nfsen/profiles-data/live/ipfix-global
  netflow     31     1  0 05:57 ?        00:00:00 /usr/bin/perl -w /data/nfsen/bin/nfsend
  netflow     32    31  0 05:57 ?        00:00:00 /data/nfsen/bin/nfsend-comm
  root       680   123  0 06:19 ?        00:00:00 grep nf

Other nfsen command parameters are well documented in the man pages. Basics are:

    Root commands:
    The commands below are only accepted, when running nfsen as root.

  Start
  Start nfsen. Can be linked from init.d, rc.d directories to start/stop nfsen

  Stop
  Stop nfsen. Can be linked from init.d, rc.d directories to start/stop nfsen

    reconfig
    Reconfigure nfsen, when adding/deleting netflow sources. First make the
    appropriate changes in nfsen.conf and then run 'nfsen reconfig'. The nfcapd
    collectors are started or stopped as needed. In case of a source removal, all
    netflow data is deleted.

    status
    Prints the status of all collectors and nfsend.

One annoying thing is if nfsen/nfdump are out of time sync w/apache. An indicator of this is if in the `/data/nfsen/profiles-data/live/` directory the nfcapd capture time stamps arent jiving w/ your rrd graphs. To avoid too confusion, the container is set to **UTC**. If you look in the Dockerfile that is explicitly set in the `php.ini` files. Debian also maintains two php.ini files, one for a sandbox and the other for prod. Both are modified for consistency.

Configure php with the systems timezone, modifications are tagged with the word `NFSEN_OPT` for future ref:

  RUN sed -i 's/^;date.timezone =/date.timezone \= \"UTC\"/g' /etc/php5/apache2/php.ini
  RUN sed -i '/date.timezone = "UTC\"/i ; NFSEN_OPT Adjust your timezone for nfsen' /etc/php5/apache2/php.ini
  RUN sed -i 's/^;date.timezone =/date.timezone \= \"UTC\"/g' /etc/php5/cli/php.ini
  RUN sed -i '/date.timezone = "UTC\"/i ; NFSEN_OPT Adjust your timezone for nfsen' /etc/php5/cli/php.ini

Get the UUID of the running container with `docker ps ls`:

  $ docker ps ls

  CONTAINER ID        IMAGE               COMMAND                CREATED             STATUS              PORTS                                                                                                                                                       NAMES
  aba11747ca4c        nflow_debian:v1     "/bin/sh -c 'bash -C   22 minutes ago      Up 22 minutes       9996/tcp, 4739/tcp, 2055/tcp, 514/tcp, 0.0.0.0:80->80/tcp, 0.0.0.0:2055->2055/udp, 0.0.0.0:4739->4739/udp, 0.0.0.0:6343->6343/tcp, 0.0.0.0:9996->9996/udp   nfsen

View container settings from the Docker host with Docker inspect:

  $ docker inspect aba11747ca4c

Grep for network setting like so:

  docker inspect aba11747ca4c | grep -A 45 NetworkSettings
      "NetworkSettings": {
          "Bridge": "docker0",
          "Gateway": "172.17.42.1",
          "IPAddress": "172.17.0.145",
          "IPPrefixLen": 16,
          "MacAddress": "02:42:ac:11:00:91",
          "PortMapping": null,
          "Ports": {
              "2055/tcp": null,
              "2055/udp": [
                  {
                      "HostIp": "0.0.0.0",
                      "HostPort": "2055"
                  }
              ],
              "4739/tcp": null,
              "4739/udp": [
                  {
                      "HostIp": "0.0.0.0",
                      "HostPort": "4739"
                  }
              ],
              "514/tcp": null,
              "6343/tcp": [
                  {
                      "HostIp": "0.0.0.0",
                      "HostPort": "6343"
                  }
              ],
              "80/tcp": [
                  {
                      "HostIp": "0.0.0.0",
                      "HostPort": "80"
                  }
              ],
              "9996/tcp": null,
              "9996/udp": [
                  {
                      "HostIp": "0.0.0.0",
                      "HostPort": "9996"
                  }
              ]
          }
      },
      "Path": "/bin/sh",
      "ProcessLabel": "",

Install `net-tools` to get netstat installed on the container and docker host if not already present.

  apt-get install net-tools

Example option to view IP port bindings:

  $ netstat -lntu

  Active Internet connections (only servers)
  Proto Recv-Q Send-Q Local Address           Foreign Address         State
  tcp6       0      0 :::80                   :::*                    LISTEN
  udp        0      0 0.0.0.0:2055            0.0.0.0:*
  udp        0      0 0.0.0.0:6343            0.0.0.0:*
  udp        0      0 0.0.0.0:4739            0.0.0.0:*
  udp        0      0 0.0.0.0:9996            0.0.0.0:*

Netstat flags are:

  * -l = only services which are listening on some port
  * -n = show port number, don't try to resolve the service name
  * -t = tcp ports
  * -u = udp ports
  * -p = name of the program

Look for nfcapd files to be populated in the directory defined in `/data/nfsen/etc/nfsen.conf` that the `install.pl` generated:

  root@aba11747ca4c:/# ls -lt /data/nfsen/profiles-data/zone1_profile/
  total 32
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 dns
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 http
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 http-alt
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 icmp
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 ssh
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 https
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 telnet
  drwxrwxr-x 3 netflow www-data 4096 Feb 15 06:45 ntp

## Next Steps - Setup the Global Agreggator

The Global Analytics Agreggator is a seperate container that resides above the granular flow collectors that reside on each Physical node. The data agregattor will reduce the signal to noise ratio of the data and only ingest data that fits the profile nessecary for the analytical use case as defined by the users policy.

### Contributing and Future Features

Please feel free to jump in on this project. It is integrating community software and building on top of it. Much of the custom work will be done building the Agreggator harness so take a peak there also.

- RPC calls to add an export target will be performed via OVSDB and eventually mix in the configuration data for correlation between ephemral state events such as a spike in flow data from an IP address that can query either orchestration that is maintaining address mappings, extracted from the flow export protocol or query a cache from ecosystem frameworks.

- Query EGP/IGP network protocols for network state that can add further visibility for location and any other interesting use cases that can be hacked together having rich data sets.

- Add an API to the ccollector side to install policy filters from the central.

### Deprecated info from original README

**Note:** I did this a long time ago. Pre-fig etc. Needs updating to be useful. It is used to setup nfsen/nfdump that can then be pushed to a global collector.

The first container in the set will setup the local collector  to be installed on every host. While the local collector listens on IP ports and can be oversubscribed, it is interesting to view network collection and analytics as becoming fully distributed along with packet-forwarding and the trend is disagregated network services.  Transitioning network service and management to a scale out architecture on general purpose compute is the primary CapEx savings SDN presents in the data center and beyond.

### QuickStart - Pre-Requisite running Docker instance

***- Docker Installations by OS***

- **(Mac)** Boot2Docker Installation:
Boot2Docker is the Mac Docker application that is a thin Linux instance tightly integrated into your Mac environment.
boot2docker Docker Doc Instructions
https://github.com/boot2docker/boot2docker

- **(Linux Debian)**: [Docker Debian Installation](https://docs.docker.com/installation/debian/)
- **(Linux Fedora)**: [Docker Fedora Installation](https://docs.docker.com/installation/fedora/)
- **(Linux Ubuntu)**: [Docker Ubuntu Installation](https://docs.docker.com/installation/ubuntulinux/)
- **(Linux CentOS)**: [Docker CentOS Installation](https://docs.docker.com/installation/centos/)
- All OS Distributions can be found at [Docker Documentation](https://docs.docker.com/installation/)

---

You should see supervisord start the apache daemons in the terminal like so:

  2015-02-22 04:12:27,903 INFO success: sshd entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
  2015-02-22 04:12:27,903 INFO success: apache2 entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

**Note:** The container starts sshd: there are many reason not to run sshd but for getting your container image tweaked to how you want it and initial tshooting, some shell access is necessary for most. 


