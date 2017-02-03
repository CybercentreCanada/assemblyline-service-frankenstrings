#!/usr/bin/env python

import os


def install(alsi):

    alsi.sudo_apt_install('libyaml-dev')
    alsi.sudo_apt_install('python-Levenshtein')  # For fuzzywuzzy
    local_fuzzy = os.path.join(alsi.alroot, 'support/flarefloss/fuzzywuzzy-master.zip')
    local_vivisect = os.path.join(alsi.alroot, 'support/flarefloss/vivisect-master.zip')
    local_vivutils = os.path.join(alsi.alroot, 'support/flarefloss/viv-utils-master.zip')
    local_flare = os.path.join(alsi.alroot, 'support/flarefloss/flare-floss-master.zip')

    alsi.fetch_package('flarefloss/fuzzywuzzy-master.zip', local_fuzzy)
    alsi.fetch_package('flarefloss/vivisect-master.zip', local_vivisect)
    alsi.fetch_package('flarefloss/viv-utils-master.zip', local_vivutils)
    alsi.fetch_package('flarefloss/flare-floss-master.zip', local_flare)

    alsi.runcmd('sudo pip install ' + local_fuzzy, piped_stdio=False)
    alsi.runcmd('sudo pip install ' + local_vivisect, piped_stdio=False)
    alsi.runcmd('sudo pip install ' + local_vivutils, piped_stdio=False)
    alsi.runcmd('sudo pip install ' + local_flare, piped_stdio=False)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())
