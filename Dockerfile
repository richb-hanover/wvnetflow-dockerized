# Dockerfile for Webview Netflow Reporter
# From https://sourceforge.net/projects/wvnetflow/

FROM phusion/baseimage:0.9.22
MAINTAINER Rich Brown <richb.hanover@gmail.com>

ENV USERACCT wvnetflow
ENV WVNETFLOW_VERSION 1.0.7d
ENV FLOWTOOLS_VERSION 0.68.5.1

# Use baseimage-docker's init system.
CMD ["/sbin/my_init"]

# ---------------------------
# Work as user USERACCT, not root

RUN useradd -ms /bin/bash $USERACCT 
#     && ls -al /etc/sudoers.d \
#     && echo "$USERACCT ALL=(root) NOPASSWD:ALL" > /etc/sudoers.d/$USERACCT \
#     && chmod 0440 /etc/sudoers.d/$USERACCT \
#     && ls /etc/sudoers.d \
#     && cat /etc/sudoers.d/README

# ---------------------------
# update and retrieve all packages necessary

RUN apt-get update && apt-get -y install \
    apache2 \
    automake \
    build-essential \
    byacc \
    cpanminus \
    libcflow-perl \
    libgd-gd2-perl \
    libnet-dns-perl \
    libnet-patricia-perl \
    libnet-snmp-perl \
    librrds-perl \
    libspreadsheet-writeexcel-perl \
    libtool \
    nano \
    rrdtool \
    tcpdump \
    wget \
    zlib1g-dev

RUN cpanm CGI 

# 
# Switch to $USERACCT
#
# USER $USERACCT
ENV USERHOME /home/$USERACCT
WORKDIR $USERHOME

#
# Retrieve, gunzip and untar the wvnetflow distribution and change into its root directory
#
RUN cd ~ \
  && wget https://iweb.dl.sourceforge.net/project/wvnetflow/wvnetflow/wvnetflow-1.07d.tar.gz \
  && gunzip -c wvnetflow-1.07d.tar.gz | tar -xf - \
  && cd ~/wvnetflow-1.07d

#
# Install the flowd collector.
# Webview uses a fork of the flowd source with improvements for logging and sequence number handling
#   (see http://code.google.com/r/cweinhold-flowd-sequence for more information).
#

RUN cd ~/wvnetflow-1.07d \
  && wget http://iweb.dl.sourceforge.net/project/wvnetflow/flowd-sequence/cweinhold-flowd-sequence.tar.gz \
  && gunzip -c cweinhold-flowd-sequence.tar.gz | tar -xf - \
  && cd cweinhold-flowd-sequence \
  && ./configure \
  && make install \
  && mkdir -p /var/empty/dev \
  && groupadd _flowd \
  && useradd -g _flowd -c "flowd privsep" -d /var/empty _flowd

#
# Install flow-tools and Cflow.pm.
# This requires building from the flow-tools fork at https://code.google.com/p/flow-tools/.
# (the relative directory structure for the next few steps is very important!)
# Installed into /usr/local/flow-tools/
RUN  cd ~/wvnetflow-1.07d \
     # file moved - no longer at: wget https://flow-tools.googlecode.com/files/flow-tools-0.68.5.1.tar.bz2
  && wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/flow-tools/flow-tools-0.68.5.1.tar.bz2 \
  && bzcat flow-tools-0.68.5.1.tar.bz2 | tar -xf - \
  && cd flow-tools-0.68.5.1/ \
  && patch -p1 <../optional-accessories/flow-tools-patches/patch.flow-tools.scan-and-hash \
  && ./configure \
  && make \
  && make install 

#
# Set up rsyslogd -- first, add socket listener for flowd chroot log file:
#
# RUN sed -i.bak -e '/GLOBAL DIRECTIVES/i $AddUnixListenSocket /var/empty/dev/log\n' /etc/rsyslog.conf
# COPY docker_scripts/40-flowd.conf /etc/rsyslog.d/40-flowd.conf
# RUN chmod +x /etc/rsyslog.d/40-flowd.conf

#
# create directories and install the wvnetflow files into /usr/local/webview directories
#
RUN  cd ~/wvnetflow-1.07d \
  && mkdir -p /opt/netflow/tmp \
  && mkdir -p /opt/netflow/data \
  && mkdir -p /opt/netflow/cache \
  && mkdir -p /opt/netflow/capture \
  && chown -R $USERACCT:$USERACCT /opt/netflow \
  && mkdir -p /usr/local/webview \
  && cp -Rp flowage www utils /usr/local/webview \
  && cp etc/webview.conf /etc \
  && chmod 777 /usr/local/webview/www/flow/graphs \
  && chown -R www-data:www-data /usr/local/webview/www/flow

#
# set up flowd init script for runit (in /etc/service/flowd/run)
#
RUN  cd ~/wvnetflow-1.07d \
  && cp etc/flowd-2055.conf /usr/local/etc/ \
  && mkdir /etc/service/flowd 
COPY docker_scripts/flowd.sh /etc/service/flowd/run 
RUN  chmod +x /etc/service/flowd/run \
  && touch /var/log/flowd
# && ln -s /etc/init.d/flowd /etc/init.d/flowd-2055 
# && update-rc.d flowd-2055 defaults 
# && service flowd-2055 start

# (Note that multiple flowd init scripts and config files can coexist. The
# "-number" is the port number of the listener. It's good form to use a different
# listener port for each type of collection -- e.g., MPLS WAN routers might use
# port 2055, while outside internet routers could use 2056 and data center
# switches could use 2057).

#
# create crontab from wvnetflow commands
WORKDIR $USERHOME
COPY docker_scripts/newcron .
RUN  crontab newcron
  
#
# set up web server
#
COPY docker_scripts/replacement-index.html /var/www/html/index.html
RUN sed -i.bak -e'/<\/VirtualHost>/ i \
  Alias "/webview" "/usr/local/webview/www" \n\
  \n\
  <Directory /usr/local/webview/www> \n\
       Options Indexes Includes FollowSymLinks ExecCGI \n\
       # order allow,deny \n\
       Require all granted \n\
       SetEnv no-gzip 1 \n\
       # allow from all \n\
       AddHandler cgi-script .cgi \n\
  </Directory> \n\
' /etc/apache2/sites-available/000-default.conf \
  && a2enmod cgi \
  && mkdir /etc/service/apache2
COPY docker_scripts/apache.sh /etc/service/apache2/run 
RUN chmod +x /etc/service/apache2/run

# Manually set up the apache environment variables
# ENV APACHE_RUN_USER www-data
# ENV APACHE_RUN_GROUP www-data
# ENV APACHE_LOG_DIR /var/log/apache2
# ENV APACHE_LOCK_DIR /var/lock/apache2
# ENV APACHE_PID_FILE /var/run/apache2.pid# 

# Expose apache & netflow port
EXPOSE 80
EXPOSE 2055

# Configure Startup Process
# WORKDIR /
# COPY docker_scripts/startup.sh . # 

# # Configure supervisord
# COPY docker_scripts/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
# RUN  touch /var/log/supervisord.log \
#   && chown wvnetflow:wvnetflow /var/log/supervisord.log


