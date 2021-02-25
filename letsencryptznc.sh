#! /usr/bin/env bash
# This script renews the let's encrypt certificate for ZNC
zncdir='/usr/local/etc/znc'
letsencryptdir="/usr/local/etc/letsencrypt/live/`hostname`"

# Let certbot do it's thing
if [[ -x `which certbot` ]]; then
    certbot renew
	# echo "This is when we'd run the certbot renew"
else
    echo "Could not find certbot, quitting"
    exit 1
fi

# Back up znc.pen if it exists
# if [[ -s ${letsencryptdir}/znc.pem ]]; then
#    mv ${letsencryptdir}/znc.pem ${letsencryptdir}/znc.pem.old
# else
#	echo "znc.pem is missing from let's encrypt dir"
#	echo "maybe it should be?"
# fi

# ZNC expects everything in one PEM, let's concatenate some files
if [[ -r ${letsencryptdir}/privkey.pem ]] && [[ -r ${letsencryptdir}/cert.pem ]]; then
    cp ${letsencryptdir}/privkey.pem ${letsencryptdir}/znc.pem
    cat ${letsencryptdir}/cert.pem >> ${letsencryptdir}/znc.pem
else
    echo "Could not read files needed for pem"
    exit 1
fi

# Let's be reasonable here, make a backup
if [[ -s ${zncdir}/znc.pem.old ]]; then
    rm ${zncdir}/znc.pem.old
else
    echo "Tried to delete znc.pem.old but it's missing"
fi
mv ${zncdir}/znc.pem ${zncdir}/znc.pem.old

# Move the new cert into place
mv ${letsencryptdir}/znc.pem ${zncdir}/

# Keep it secret, keep it safe
chmod 600 ${zncdir}/zmc.pem
chown znc:znc ${zncdir}/zmc.pem

# Restart the service
service znc restart
