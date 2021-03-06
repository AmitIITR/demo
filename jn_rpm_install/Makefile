
PACKAGE_VERSION := 0.1
RPM_REVISION := 1

# Various commands we need.
MKDIR_P := mkdir -p
CP_P := cp -p
# In some environment this command can be called `gsha1sum' or `digest'.
SHA1SUM := sha1sum
ZIP := zip -9
PYTHON_VERSION := 2.6
PYTHON := python$(PYTHON_VERSION)

# Our "source tree" is in the parent directory, always.
VPATH := ..

git_version := \
  `git rev-list --pretty=format:%h HEAD --max-count=1 | sed 1d || echo unknown`
git_fullsha1 := \
  `git rev-list --pretty=format:%H HEAD --max-count=1 | sed 1d || echo unknown`

# What / where do we build.
RPM_TARGET := x86_64
BASENAME := beacon-$(PACKAGE_VERSION)-$(RPM_REVISION)
RPM := $(BASENAME).$(RPM_TARGET).rpm
SRPM := $(BASENAME).src.rpm
EOSRPM := beacon-eos-$(PACKAGE_VERSION)-$(RPM_REVISION).$(RPM_TARGET).rpm
SWIX := $(BASENAME).swix

all: rpm swix

$(SWIX): manifest.txt $(EOSRPM) $(RPM) $(COLLECTORSRPM)
	$(ZIP) $@ $^

swix: $(SWIX)

manifest.txt: Makefile
	set -e; { \
          echo 'format: 1'; \
          echo 'primaryRpm: $(EOSRPM)'; \
	  for rpm in $(EOSRPM) $(RPM) $(COLLECTORSRPM); do \
            echo -n "$$rpm-sha1: "; \
            set `$(SHA1SUM) "$$rpm"`; \
            echo $$1; \
          done; \
        } >$@

rpm:
	set -e; { \
          echo "# File generated by Makefile, do not edit"; \
	  sed \
            -e 's/@PACKAGE_VERSION@/$(PACKAGE_VERSION)/' \
	    -e 's/@PYTHON_VERSION@/$(PYTHON_VERSION)/' \
            -e "s/@GIT_SHORTSHA1@/$(git_version)/" \
            -e "s/@GIT_FULLSHA1@/$(git_fullsha1)/" \
            -e 's/@RPM_REVISION@/$(RPM_REVISION)/' \
	    beacon.spec; \
        } >beacon-t.spec
	rpmbuild --define "_topdir %(pwd)/" \
	   --define "_sourcedir %(pwd)/dist/" \
          --define "_rpmdir %(pwd)" \
          --define "_srcrpmdir %{_topdir}" \
          -bb beacon-t.spec
	if test -f $(RPM_TARGET)/$(RPM); then mv $(RPM_TARGET)/$(RPM) .; else mv beacon.$(RPM_TARGET).rpm $(RPM); fi

clean:
	rm -rf beacon-t.spec manifest.txt bld dist tmp $(RPM_TARGET)

distclean: clean
	rm -f $(SWIX) $(RPM) $(SRPM) $(COLLECTORSRPM) $(EOSRPM)

.PHONY: all rpm clean distclean swix
.SUFFIXES: .spec .rpm
