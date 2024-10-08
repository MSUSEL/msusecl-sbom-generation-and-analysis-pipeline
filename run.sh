#!/bin/bash

# Run acquisition.sh
echo "Running acquisition.sh..."
./acquisition.sh

# Check the exit status of acquisition.sh
if [ $? -ne 0 ]; then
    echo "acquisition.sh failed"
    exit 1
fi

# Run evaluate.sh
echo "Running evaluate.sh..."
./evaluate.sh

# Check the exit status of evaluate.sh
if [ $? -ne 0 ]; then
    echo "evaluate.sh failed"
    exit 1
fi

# Run preprocessing.sh
echo "Running preprocessing.sh..."
./preprocessing.sh

# Check the exit status of evaluate.sh
if [ $? -ne 0 ]; then
    echo "preprocessing.sh failed"
    exit 1
fi

# Run data_analysis.sh
echo "Running data_analysis.sh..."
./data_analysis.sh

# Check the exit status of evaluate.sh
if [ $? -ne 0 ]; then
    echo "data_analysis.sh failed"
    exit 1
fi

echo "All scripts executed successfully."

# Exit with a success status
exit 0
