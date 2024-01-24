#!/bin/bash

if [ "$1" == "default" ]; then

	echo "Activate virtual environment"
	source venv/bin/activate

	echo "Run processor.py on $2"
	saas-cli run --job-path $2 --proc-path `pwd` --proc-name example-processor --rest-address $3

elif [ "$1" == "nscc" ]; then

	echo "Load python module"
	module load python/3.8.3

	echo "Activate virtual environment"
	source venv/bin/activate

	echo "Run processor.py on $2"
	python3 processor.py $2

else
	exit 1
fi


