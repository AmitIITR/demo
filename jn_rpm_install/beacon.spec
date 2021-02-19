
#%%define debug_package 1

%global inceptiondir /usr/local/inception
%global inceptionlddir /usr/local/inception/ld
%global beacon_rundir /etc/init.d/ 
%global ld_conf_dir /etc/ld.so.conf.d/ 
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
mkdir -p %{buildroot}/ld_conf_dir
%{__install} -m 0755 -D %{rootdir}/ld_preload/libinceptionappagent.conf %{buildroot}/%{ld_conf_dir}/libinceptionappagent.conf
%{__install} -m 0755 -D %{rootdir}/ld_preload/libinceptionappagentproc.so %{buildroot}/%{inceptionlddir}/libinceptionappagentproc.so


# Install Base files
%{__install} -m 0755 -D %{rootdir}/BUILD/beacon-@PACKAGE_VERSION@/beacon %{buildroot}/%{inceptiondir}/beacon


%files
%dir %{inceptiondir}
%{inceptiondir}/beacon
%{inceptionlddir}/libinceptionappagentproc.so
%{beacon_rundir}/beacon
%{ld_conf_dir}/libinceptionappagent.conf
%doc

%changelog

