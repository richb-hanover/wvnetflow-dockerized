# Webview Netflow Reporter

A dockerized container to run Webview Netflow Reporter by Craig Weinhold craig.weinhold@cdw.com
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

