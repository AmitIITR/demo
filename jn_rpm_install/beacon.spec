%global beacon_rundir /etc/init.d/ 
%global rootdir       %{_topdir}
Name:		beacon		
Group:          System/Monitoring
Version:        @PACKAGE_VERSION@
Release:        @RPM_REVISION@
Distribution:   buildhash=@GIT_FULLSHA1@
License:        LGPLv3+
Summary:	Beacon - Data collection and system monitoring agent for inception
URL:            http://example.com/beacon.html
Source0:        beacon.tar.gz
Provides:       beacon = @PACKAGE_VERSION@-@RPM_REVISION@_@GIT_SHORTSHA1@
Packager:       Beacon Maintainers <amit@inceptioncloud.io>
Requires:       initscripts
Requires:       python(abi) >= @PYTHON_VERSION@
Requires:       python-devel
Requires:       MySQL-python
Requires:       python-requests
Requires:       PyYAML

%description
Beacon is the system agent for Inception. It is respobnsible for 
autodiscovery of processes, applying exporters, java remote attach and 
pushing the metrix to Inception metric store.


%prep
%setup -q


%build


%install
mkdir -p %{buildroot}/etc/init.d/

# set homedir in init script
%{__perl} -pe "s|HOMEDIR|%{beacon_rundir}|;" -i %{rootdir}/rpm/initd.sh
# Install the init.d
%{__install} -m 0755 -D %{rootdir}/rpm/initd.sh %{buildroot}/etc/init.d/beacon

%files
%dir %{beacon_rundir}
%{beacon_rundir}/beacon
%doc



%changelog

