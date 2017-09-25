# renderspec (OBS source service) 
[![Build Status](https://travis-ci.org/openSUSE/obs-service-renderspec.svg?branch=master)](https://travis-ci.org/openSUSE/obs-service-renderspec)

This is an [Open Build Service](http://openbuildservice.org/) source service for rendering .spec.j2 templates with [renderspec](https://pypi.python.org/pypi/renderspec).

This is the git repository for [openSUSE:Tools/obs-service-renderspec](https://build.opensuse.org/package/show/openSUSE:Tools/obs-service-renderspec). The authoritative source is https://github.com/openSUSE/obs-service-renderspec

## Requirements
`python-requests`, `python-six`, `renderspec` and the OBS source service `download_files`.

## Testing
The tests can be called with:

    python tests/test_base.py
