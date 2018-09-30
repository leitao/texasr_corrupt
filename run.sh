#!/bin/bash

function check_texasr_in_coredump() {
	if [ ! -f "core" ]; then
		echo "Coredump file not generated in this directory"
		exit -1
	fi

	TEXASR=$(eu-readelf --notes core | grep texasr | awk '{print $4}')

	if [ $TEXASR == "0x0000000000000007" ];
	then
		echo Passed. TEXASR = $TEXASR
	else
		echo Failed! Corrupted TEXASR = $TEXASR
		exit -1
	fi
}


# allow coredump generation
ulimit -c unlimited

z=1
# Amount of cycles that is expected to have load_tm = 0
for i in 100 3489660928 7489660928;
do
	echo "Starting test (${z}/3)"
	./test $i
	retVal=$?

	if [ $retVal -ne 0 ]; then
		echo "Error executing test."
	fi

	# Analyze coredump and check TEXASR value
	check_texasr_in_coredump
	z=$(($z+1))
	echo
done

