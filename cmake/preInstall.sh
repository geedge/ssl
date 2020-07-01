#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/protocol/
mkdir -p ${DST}/etc/
touch ${DST}/plug/conflist.inf
touch ${DST}/etc/entrylist.conf
if [[ -z `grep -rn 'ssl.inf' ${DST}/plug/conflist.inf` ]];then
	sed -i '/\[protocol\]/a\./plug/protocol/ssl/ssl.inf' ${DST}/plug/conflist.inf
fi
if [[ -z `grep -rn 'SSL' ${DST}/etc/entrylist.conf` ]];then
	echo "SSL" >>  ${DST}/etc/entrylist.conf
fi
