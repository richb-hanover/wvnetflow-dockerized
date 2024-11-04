# Installation Guide for Webview Netflow Reporter on Debian LXC

**Date:** 2024-11-03
**OS Version:** Debian 12 (bookworm)
**Host:** Proxmox
**Host Version:** pve-manager/8.2.2/9355359cd7afbae4 (running kernel: 6.8.4-2-pve)

## Overview

This document walks through the setup of `wvnetflow` in a Debian LXC container, from installing Docker to configuring network monitoring. We’ll cover:

1. Installing Docker within the LXC container
2. Configuring `wvnetflow` to receive NetFlow data
3. Setting up `softflowd` on OpenWRT to send NetFlow data to `wvnetflow`

## Prerequisites

- **Debian LXC**: Start with a fresh container (Debian 12 was used at the time of authoring this).
- **Docker**
- **OpenWRT Router**

## Steps

### Installing Docker

1. Update package list and install prerequisites.

    ```sh
    sudo apt update -y
    sudo apt install -y ca-certificates curl gnupg lsb-release
    ```

2. Add Docker’s official GPG key.

    ```sh
    sudo mkdir -m 0755 -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    ```

3. Set up the Docker repository.

    ```sh
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    ```

4. Install Docker, including the Docker Compose plugin.

    ```sh
    sudo apt update -y
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ```

5. Enable and start Docker.

    ```sh
    sudo systemctl enable docker
    sudo systemctl start docker
    ```

### Clone and Build `wvnetflow`

First, clone the `wvnetflow` repository and navigate into the directory:

```sh
git clone https://github.com/richb-hanover/wvnetflow-dockerized.git
cd wvnetflow-dockerized
```

### Set Up Volume Directory for Netflow Data

The `/opt/netflow` directory inside the container must be mapped to an external volume for persistent storage. Create this directory and ensure subdirectories are set up correctly.

1. **Create the volume directory** on the host:

    ```sh
    sudo mkdir -p /mnt/your-drive/netflow
    ```

2. **Create necessary subdirectories:**

    ```sh
    sudo mkdir -p /mnt/your-drive/netflow/cache /mnt/your-drive/netflow/capture /mnt/your-drive/netflow/data /mnt/your-drive/netflow/tmp
    ```

3. **Set permissions** for these directories to ensure the container can access them:

    ```sh
    sudo chmod -R 777 /mnt/your-drive/netflow
    ```

    _Note: You can use a more restrictive permission than `777` if you want, so long as your container can read/write to this directory._

### Configure Docker Compose

Edit the `docker-compose.yml` file in the `wvnetflow-dockerized` directory to set the volume path for the Netflow data and any necessary timezone adjustments:

```yaml
services:
  wvnr:
    build:
      context: .
    image: wvnr_img
    container_name: wvnr_img
    volumes:
      - /mnt/your-drive/netflow:/opt/netflow  # Update path as necessary
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      - "83:80"
      - "2055:2055/udp"
    environment:
      - TZ=America/New_York  # Adjust timezone as necessary
    restart: unless-stopped
```

### Build and Start the wvnetflow Container

Build the container image and launch the container:

```sh
docker compose up --build -d
```

### Configure `softflowd` on OpenWRT

1. **Install** `softflowd` on your OpenWRT router:

    ```sh
    opkg update
    opkg install softflowd
    ```

2. **Edit** `/etc/config/softflowd` to configure your interfaces:

    On my router, I have a primary and guest LAN both configured to send netflow. Each interface must be configured as a separate process.

    ```sh
    config softflowd 'instance_lan'
        option enabled        '1'
        option interface      'br-lan'
        option host_port      '192.168.1.xxx:2055'  # IP of wvnetflow container host
        option max_flows      '8192'
        option export_version '5'
        option pid_file       '/var/run/softflowd_lan.pid'
        option control_socket '/var/run/softflowd_lan.ctl'
        option tracking_level 'full'
        option track_ipv6     '0'
        option bidirectional  '0'
        option sampling_rate  '1' # Set the 1 if you want to capture every packet

    config softflowd 'instance_guest'
        option enabled        '1'
        option interface      'br-guest'
        option host_port      '192.168.1.xxx:2055'
        option max_flows      '8192'
        option export_version '5'
        option pid_file       '/var/run/softflowd_guest.pid'
        option control_socket '/var/run/softflowd_guest.ctl'
        option tracking_level 'full'
        option track_ipv6     '0'
        option bidirectional  '0'
        option sampling_rate  '1'
    ```

3. **Restart** `softflowd` to apply these changes:

    ```sh
    /etc/init.d/softflowd restart
    ```

### Access Webview Netflow Reporter

Wait 15-30 minutes, then access the web interface at http://<container_host_ip>:83. You should see data appearing in the ad hoc tool and graphing mechanism.

## Troubleshooting

* **Viewing Docker Logs:** To check for any errors or status messages from the container, use:

    ```sh
    docker compose logs -f
    ```

    This command shows the container logs in real time. Look for any errors related to network connections, permissions, or general container operation.

* **Confirming Netflow Data is Being Sent from OpenWRT:**

    To ensure that `softflowd` on OpenWRT is actively exporting Netflow data to the wvnetflow container, you can:

    1. **Check the `softflowd` process:** Verify that softflowd is running for each configured interface:

        ```sh
        ps | grep softflowd
        ```

    2. **Check general OpenWRT logs:** Use the `logread` command to see if any logs are being generated that could indicate issues with network interfaces, softflowd crashes, or related services.

    3. **Verify Network Data:** You can use `tcpdump` to directly verify if Netflow data is being exported. Run this command on OpenWRT to see if UDP packets are being sent to the Netflow analyzer:

        ```sh
        tcpdump -n -i any udp port 2055
        ```

        This should show packets flowing out to the IP and port where your Netflow analyzer is running (e.g., your Docker container’s host).

    4. **Check OpenWRT’s service status:** OpenWRT uses `procd` to manage services. Restarting `softflowd` using OpenWRT’s service command may produce additional log entries if it encounters issues:

        ```sh
        /etc/init.d/softflowd restart
        ```

    5. **Review Configuration:** Double-check your softflowd configuration in `/etc/config/softflowd` for any possible misconfigurations.
