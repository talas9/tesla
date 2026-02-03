#!/bin/sh

DIR="/tmp/mcu"
NAME=$1

readSignatures()
{
        rm -R "$DIR" >/dev/null 2>&1
        mkdir "$DIR"
        mount "$NAME" "$DIR"

        version_path="$DIR/tesla/UI/bin/version.txt"
        version=$(cat "$version_path")
        echo "${version}"

        sig=$(tail -c64 "$NAME" | base64 -w 0)
        echo "Sig: ${sig}"

        md5=$(md5sum "$NAME" | awk '{ print $1 }')
        echo "MD5: $md5"

        ape_path="$DIR/deploy/ape.sig"
	        ape_sig=$(tail -c64 "$ape_path" | base64 -w 0)
	        echo "ape sig: ${ape_sig}"

        ape25_path="$DIR/deploy/ape25.sig"
	        ape25_sig=$(tail -c64 "$ape25_path" | base64 -w 0)
	        echo "ape25 sig: ${ape25_sig}"

        
        ape3_path="$DIR/deploy/ape3.sig"
	        ape3_sig=$(tail -c64 "$ape3_path" | base64 -w 0)
	        echo "ape3 sig: ${ape3_sig}"

        umount "$DIR"
        rm -R "$DIR" >/dev/null 2>&1
}

if [ -z $NAME ]
then
   echo "Please enter the FW name as parameter";
else
   readSignatures
fi
