# Overview - Webview Netflow Reporter

A lightweight Netflow collector and web display tool based on wvnetflow and flow-tools in a Docker container. Webview Netflow Reporter was created by Craig Weinhold craig.weinhold@cdw.com. 

This container listens on ports 2055 for netflow exports, and 
displays the collected data in a web interface.
This screenshot shows off the varying data sent through a router.

![wvnetflow screen shot](https://github.com/richb-hanover/wvnetflow-dockerized/raw/master/images/wvnetflow-screenshot.png)
For more information and screenshots, see [wvnetflow](http://wvnetflow.sourceforge.net/) hosted at [SourceForge.net](SourceForge.net)

*Testing Status: This container has been tested with 
Docker Community Edition Version 17.03.1-ce-mac5 (16048) 
running on a mid-2011 Mac mini, OSX 10.12.4, 
with a 2.3 GHz Intel Core i5 processor and 8 GBytes RAM. 
It works great with my LEDE/OpenWrt router after installing the softflowd package to export netflow info.
If you try it out, please file an issue and let me know how it worked for you.* 

### QuickStart - Install and Test Webview Netflow Reporter

1. Install [Docker](https://www.docker.com/community-edition) (the Community Edition works fine) on a computer that's always running. wvnetflow will run there and collect the netflow data 24x7.

1. Clone the *wvnetflow-dockerized* repo to that computer.
 
    ```
    $ git clone https://github.com/richb-hanover/wvnetflow-dockerized.git
    ``` 
2. Build the container from the Dockerfile, giving it the name *wvnr_img*

    ```
    $ cd wvnetflow-dockerized
    $ docker build -t wvnr_img .
    ```
3. Run the container named *wvnr_img*. This will print a container-ID on the console.

    ```
  $ docker run -d -p 83:80 -p 2055:2055/udp --name wvnr_img wvnr_img
9c1b567e0aba007368ed062d4aa226675fa1e011600cdf59593d42a689d05034
    ```

5. Point your web browser to [http://localhost:83](http://localhost:83/) You will see the Webview Netflow Reporter home page. (**Note:** The `docker run...` command above maps external port 83 to the docker container's web port 80.)

   <img src="https://github.com/richb-hanover/wvnetflow-dockerized/raw/master/images/wvnetflow-home.png" width="500" />

7. Configure your router(s) to export Netflow version 5 flows to port 2055 on this collector, or generate mock flow data (see below). 

8. **Wait...** It can take many minutes before the flow data has been collected and displayed. Read the Troubleshootings steps (below) to see if the machinery is working...

### QuickStart - Other setup information and tests

* To connect to the container via a terminal, use this command:

    ```
    $ docker exec -i -t wvnr_img /bin/bash
    ```
* Add "-d" to daemonize the container when you run it (e.g., `docker run -d -p ...`) This allows you to continue working in the same terminal window. 

* To make a change to the container, stop it with the command below (this removes the "wvnr_img" name), edit the Dockerfile, then rebuild and `docker run`...

    ```
    $ docker rm -f wvnr_img
    ```
* The container opens these ports:

  * Apache default port `EXPOSE 80`
  * NetFlow default port `EXPOSE 2055`
  
* Verify the port bindings between internal ports (2055 & 80) and their external mappings using `docker port image_name`

   ```
   $ docker port wvnr_img
   2055/udp -> 0.0.0.0:2055
   80/tcp -> 0.0.0.0:83
   ```

### QuickStart - www access

In the list should be the Apache port if no other process was already bound to the port and now point your browser at the container like so (*Note* there will not be any flows in the RRD graphs until we generate some in the next section):

    http://localhost:83/  # or use your computer's IP address

### Troubleshooting

This information is a brief, but not complete, description of the facilities. 

1. The [webview status](http://localhost:83/webview/flow/weblog.cgi) link on the home page displays a number of stats about the wvnetflow server's operation.

2. The [flow stats](http://localhost:83/webview/flow/exporter.cgi) page lists the exporters that are providing netflow data.

3. The [flowage.cfg](http://localhost:83/webview/flow/configdump.cgi) page shows the configuration file for the /usr/local/webview/flowage/flowage.pl program that drives wvnetflow.

### Modifying the Docker Image ###

This is a Docker container. The following commands are useful:

```

# build the container
$ cd <folder-containing-wvnetflow>
$ docker build -t wvnr_img . 

# run the container, listening on external ports 83 for http and 22055 for netflow records
# Connect your web browser to http://localhost:83/webview
$ docker run -d -p 83:80 -p 22055:2055/udp --name wvnr_img wvnr_img

# 'ssh' into the container so you can look around
$ docker exec -i -t wvnr_img /bin/bash

# When you're done (or want to modify the Dockerfile)...
# This removes the name 'wvnr_img' for re-use with next docker run...
$ docker rm -f wvnr_img
```

----------

## Provisional information - not well tested
### QuickStart - generate and view mock flows

There is a Go based netflow generator. It's at [https://github.com/nerdalert/nflow-generator](https://github.com/nerdalert/nflow-generator)

Note: The flow generator will at some point support choosing what protos and other parameters, but for now it just generates a handful of protocols and the same src/dst netflow payload addresses. As a result some of the protocol filters will be empty in the included protocol filters as seen in the following following screenshots.

Run the generator against the localhost with the following:

```
  $ flow-generator  -t 127.0.0.1 -p 2055
```

or 

```
docker run -it --rm networkstatic/nflow-generator -t <ip> -p <port>
```

