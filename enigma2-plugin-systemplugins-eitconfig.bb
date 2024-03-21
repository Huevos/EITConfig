DESCRIPTION = "tool to set up EIT config files"
MAINTAINER = "Huevos"

inherit gitpkgv allarch ${PYTHON_PN}native

require conf/license/license-gplv2.inc

PV = "1.0+git${SRCPV}"
PKGV = "1.0+git${GITPKGV}"

SRCREV = "${AUTOREV}"

SRC_URI = "git://github.com/Huevos/EITConfig.git;protocol=https;branch=master"



S = "${WORKDIR}/git"

pluginpath = "/usr/lib/enigma2/python/Plugins/SystemPlugins/EITConfig"

do_install:append() {
	install -d ${D}${pluginpath}
	cp -r ${S}/src/* ${D}${pluginpath}/
	python3 -m compileall -o2 -b ${D}
}

FILES:${PN} = "${pluginpath}/"

FILES:${PN}-src = "${pluginpath}/*.py"
