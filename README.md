# Overview - Webview Netflow Reporter

A lightweight Netflow collector and web display tool based on wvnetflow and flow-tools in a Docker container. Webview Netflow Reporter was created by Craig Weinhold craig.weinhold@cdw.com. 

This container listens on ports 2055 for netflow exports, and 
displays the collected data in a web interface.
This screenshot shows off the varying data sent through a router.

![wvnetflow screen shot](https://github.com/richb-hanover/wvnetflow-dockerized/raw/master/images/wvnetflow-screenshot.png)
There is much more information in the `docs` directory, and on the original [wvnetflow](http://wvnetflow.sourceforge.net/) site hosted at [SourceForge.net](SourceForge.net)

*Testing Status: This container has been tested with 
Docker Community Edition Version 17.03.1-ce-mac5 (16048) 
running on a mid-2011 Mac mini, OSX 10.12.4, 
with a 2.3 GHz Intel Core i5 processor and 8 GBytes RAM. 
It works great with my LEDE/OpenWrt router after installing the softflowd package to export netflow info.
If you try it out, please file an issue and let me know how it worked for you.* 

### QuickStart - Install and Test Webview Netflow Reporter

1. Install [Docker](https://www.docker.com/community-edition) (the Community Edition works fine) on a computer that's always running. wvnetflow will run there and collect the netflow data 24x7.

2. Clone the *wvnetflow-dockerized* repo to that computer.
 
    ```
    $ git clone https://github.com/richb-hanover/wvnetflow-dockerized.git
    ``` 
3. Build the container from the Dockerfile. The commands below build it with the name *wvnr_img*. 
This can take many minutes, since many files need to be downloaded and installed.

    ```
    $ cd wvnetflow-dockerized
    $ docker build -t wvnr_img .
    ```
4. Run the container named *wvnr_img*. This will print a container-ID on the console.

    ```
    $ docker run -d -p 83:80 -p 2055:2055/udp --name wvnr_img wvnr_img
    9c1b567e0aba007368ed062d4aa226675fa1e011600cdf59593d42a689d05034
    ```

5. Point your web browser to [http://localhost:83](http://localhost:83/) You will see the Webview Netflow Reporter home page. Notes:

   * The `docker run...` command above maps external port 83 to the docker container's web port 80. Change it to use a different external port if needed.
   * If you installed the Docker container on a separate computer, use the IP address of the computer where you're running wvnetflow.

   <img src="https://github.com/richb-hanover/wvnetflow-dockerized/raw/master/images/wvnetflow-home.png" width="500" />

6. Configure your router to export Netflow version 5 flows to port 2055 of the collector. 

7. **Wait...** It can take 15 minutes before the flow data has been collected and charted. See the Status page (below) for progress information.

### Quick Start - Home page

This information describes the links in the header bar. Read the `docs` and [wvnetflow](http://wvnetflow.sourceforge.net/) page for more details.

1. [Analysis](http://localhost:83/webview/flow/render.cgi) provides a GUI to select which traffic to chart. 
(Requires that the container run for at least 5-15 minutes before traffic is shown.)

2. [Ad Hoc Query](http://localhost:83/webview/flow/adhoc.cgi) lets you build queries to view the netflow data in different ways.

3. [Configuration](http://localhost:83/webview/flow/configdump.cgi) shows the configuration file for the /usr/local/webview/flowage/flowage.pl program that drives wvnetflow.
 
4. [Exporters](http://localhost:83/webview/flow/exporter.cgi) lists the exporters that are providing netflow data.

5. [Status](http://localhost:83/webview/flow/weblog.cgi) displays running statistics about the wvnetflow server. It will take up to five minutes before the **Flowage Activity Log** shows entries. 

6. [About](https://github.com/richb-hanover/wvnetflow-dockerized) leads to the github page that hosts the repository.

### Modifying the Docker Image

* Build the docker container. This creates an image named *wvnr_img*

   ```
   $ cd <folder-containing-wvnetflow-Dockerfile>
   $ docker build -t wvnr_img . 
   ```

* Run that newly-built image, and listen on port 83 for browser connections, and port 2055 for netflow records:

   ```
   $ docker run -d -p 83:80 -p 2055:2055/udp --name wvnr_img wvnr_img
   ```

* Add "-d" in the command above to daemonize the container when you run it (e.g., `docker run -d -p ...`) This allows you to continue working in the same terminal window. 

* Connect to the container via a terminal (like ssh), if you want to "look around" inside the container. This is not required: wvnetflow is already running and collecting data.

    ```
    $ docker exec -i -t wvnr_img /bin/bash
    ```

* To make a change to the container, stop it with the command below (this removes the *wvnr_img* name), edit the Dockerfile, then rebuild and `docker run`...

    ```
    $ docker rm -f wvnr_img
    ```
  
* Verify the port bindings between internal ports (2055 & 80) and their external mappings using `docker port image_name`

   ```
   $ docker port wvnr_img
   2055/udp -> 0.0.0.0:2055
   80/tcp -> 0.0.0.0:83
   ```

## Known Issues

1. This program only listens for a single netflow exporter sending to port 2055. 
This works great in a home networking environment, 
with a single router managing the bottleneck link to the ISP, 
and where you want to know "who's hogging the network".

   Because of the current Docker networking setup, this container cannot distinguish between multiple exporters sending flows. 
   I have not tested alternate setups (e.g., host network vs. bridge network) to see how this might change.

