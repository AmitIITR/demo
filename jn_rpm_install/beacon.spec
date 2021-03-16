
#%%define debug_package 1

%global inceptiondir /usr/local/inception
%global inceptionlddir /usr/local/inception/ld
%global beacon_rundir /etc/init.d/ 
%global rootdir       %{_topdir}

Name:		beacon		
Group:          System/Monitoring
Version:        @PACKAGE_VERSION@
Release:        @RPM_REVISION@
Distribution:   buildhash=@GIT_FULLSHA1@
License:        LGPLv3+
Summary:	Beacon - Data collection and system monitoring agent for inception.io
URL:            http://example.com/beacon.html
Source0:        beacon.tar.gz
Provides:       beacon = @PACKAGE_VERSION@-@RPM_REVISION@_@GIT_SHORTSHA1@
Packager:       Beacon Maintainers <amit@inceptioncloud.io>
Requires:       initscripts

%description
Beacon is the system agent for Inception. It is responsible for 
autodiscovery of processes, applying exporters, java remote attach and 
pushing the metrix to Inception metric store.


%prep
%setup -q


%build


%install
mkdir -p %{buildroot}/beacon_rundir
mkdir -p %{buildroot}/%{inceptiondir}
mkdir -p %{buildroot}/%{inceptionlddir}


# set homedir in init script
#%{__perl} -pe "s|HOMEDIR|%{inceptiondir}|;" -i %{rootdir}/rpm/initd.sh

# Install the init.d
%{__install} -m 0755 -D %{rootdir}/rpm/initd.sh %{buildroot}/%{beacon_rundir}/beacon

# Copy inception ld_preload library 
%{__install} -m 0755 -D %{rootdir}/ld_preload/libinceptionappagentproc.so %{buildroot}/%{inceptionlddir}/libinceptionappagentproc.so
%{__install} -m 0755 -D %{rootdir}/rpm/post_install.sh %{buildroot}/%{inceptionlddir}/post_install.sh
%{__install} -m 0755 -D %{rootdir}/rpm/post_uninstall.sh %{buildroot}/%{inceptionlddir}/post_uninstall.sh


# Install Base files
%{__install} -m 0755 -D %{rootdir}/BUILD/beacon-@PACKAGE_VERSION@/beacon %{buildroot}/%{inceptiondir}/beacon



# Install Base files
mkdir -p %{buildroot}%{inceptiondir}/conf/
%{__install} -m 0755 -D %{rootdir}/conf/* %{buildroot}%{inceptiondir}/conf/
%{__install} -m 0755 -D %{rootdir}/beacon %{buildroot}%{inceptiondir}/beacon

# Install Collectors
#%{__install} -m 0755 -D %{srccollectors}/0/*.py %{buildroot}%{collectorsdir}/0/


%files
%dir %{inceptiondir}
%{inceptiondir}/beacon
%{inceptionlddir}/libinceptionappagentproc.so
%{inceptionlddir}/post_install.sh
%{inceptionlddir}/post_uninstall.sh
%{beacon_rundir}/beacon
%doc


%pre
if [ "$1" = "2" ]; then
    # stop previous version of beacon service before starting upgrade
    service beacon stop
fi


%post
if [ -e /usr/local/inception/ld/post_install.sh]; then
  #run post_install.sh
  /usr/local/inception/ld/post_install.sh
fi

BEACON_USER="beacon"
BEACON_GROUP="beacon"

if [ -z "$(getent group $BEACON_GROUP)" ]; then
  groupadd --system $BEACON_GROUP
else
  echo "Group [$BEACON_GROUP] already exists"
fi

if [ -z "$(id $BEACON_USER)" ]; then
  useradd --system --home-dir /usr/local/beacon --no-create-home \
  -g $BEACON_GROUP --shell /sbin/nologin $BEACON_USER
else
  echo "User [$BEACON_USER] already exists"
fi

#chown -R $BEACON_USER.$BEACON_GROUP /usr/local/beacon
#chown -R $BEACON_USER.$BEACON_GROUP /var/run/beacon
#chown -R $BEACON_USER.$BEACON_GROUP /var/log/beacon

chkconfig --add beacon
    # stop previous version of xcollector service before starting upgrade
    service xcollector stop
fi

%post
if [ ! -L "/etc/xcollector" ]
then
  ln -s %{tcollectordir}/conf /etc/xcollector
fi
if [ ! -L "%{tcollectordir}/collectors/0/grok_nginx.py" ]
then
  ln -s %{tcollectordir}/grok_scraper.py %{tcollectordir}/collectors/0/grok_nginx.py
fi
if [ ! -L "%{tcollectordir}/collectors/0/grok_tomcat.py" ]
then
  ln -s %{tcollectordir}/grok_scraper.py %{tcollectordir}/collectors/0/grok_tomcat.py
fi
if [ ! -d "/var/run/xcollector" ]
then
  mkdir -p "/var/run/xcollector"
fi
if [ ! -d "/var/log/xcollector" ]
then
  mkdir -p "/var/log/xcollector"
fi

XCOLLECTOR_USER="xcollector"
XCOLLECTOR_GROUP="xcollector"

if [ -z "$(getent group $XCOLLECTOR_GROUP)" ]; then
  groupadd --system $XCOLLECTOR_GROUP
else
  echo "Group [$XCOLLECTOR_GROUP] already exists"
fi

if [ -z "$(id $XCOLLECTOR_USER)" ]; then
  useradd --system --home-dir /usr/local/xcollector --no-create-home \
  -g $XCOLLECTOR_GROUP --shell /sbin/nologin $XCOLLECTOR_USER
else
  echo "User [$XCOLLECTOR_USER] already exists"
fi

chown -R $XCOLLECTOR_USER.$XCOLLECTOR_GROUP /usr/local/xcollector
chown -R $XCOLLECTOR_USER.$XCOLLECTOR_GROUP /var/run/xcollector
chown -R $XCOLLECTOR_USER.$XCOLLECTOR_GROUP /var/log/xcollector

chkconfig --add xcollector
grep PASTE_ACCESS_TOKEN_HERE /etc/xcollector/xcollector.yml >/dev/null || service xcollector start

%preun
if [ "$1" = "0" ]; then
    # stop service before starting the uninstall
    service beacon stop
    chkconfig --del beacon
fi

%postun
# $1 --> if 0, then it is a deinstall
# $1 --> if 1, then it is an upgrade
if [ $1 -eq 0 ] ; then
    # This is a removal, not an upgrade
    #  $1 versions will remain after this uninstall

    # Clean up collectors
    rm -f /etc/init.d/beacon
    rm -f /etc/beacon

    userdel beacon
fi
if [ -e /usr/local/inception/ld/post_uninstall.sh]; then
  #run post_uninstall.sh, to remove entry from /etc/ld.so.preload
  /usr/local/inception/ld/post_uninstall.sh
    rm -f /etc/init.d/xcollector
    rm -f /etc/xcollector

    userdel xcollector
fi


%changelog

