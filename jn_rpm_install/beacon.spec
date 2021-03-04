
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
fi


%changelog

