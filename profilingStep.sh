#!/bin/bash

function profiling_func() {
    local stepno="$1"
    local description="$2"
    local memory_usage="$3"
    local timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

    if (( $(echo "$memory_usage < 0" | bc -l) )); then
        memory_usage="0"
    fi
    memory_usage="${memory_usage} MB"
    if [ -f "profiling.json" ]; then
        # Read data from profiling.json if it exists
        data=$(jq -c '.' profiling.json)
    else
        # Initialize with default data if profiling.json doesn't exist
        data='{
            "input": {
                "images": 0
            },
            "stepsProfile": [],
            "totalTime": {
                "minutes": 0,
                "seconds": 0
            },
            "totalMemory" : "0 MB"
        }'
    fi

    # Check if a step with the same number exists in the "stepsProfile" array
    step_exists=$(echo "$data" | jq --arg stepno "$stepno" '.stepsProfile[] | has($stepno)')

    if [ "$step_exists" = "true" ]; then
        # Update the existing step with the same number
        echo "Step $stepno exists"
        updated_data=$(echo "$data" | jq --arg stepno "$stepno" --arg description "$description" --arg timestamp "$timestamp" --arg memory_usage "$memory_usage" '.stepsProfile[] |= if has($stepno) then .[$stepno].description = $description | .[$stepno].timestamp = $timestamp | .[$stepno].memory_usage = $memory_usage else . end')
    else
        # Construct the step object
        local step_object="{\"step$stepno\": {\"description\": \"$description\", \"timestamp\": \"$timestamp\", \"memory_usage\": \"$memory_usage\"}}"
        # Add the step object to 'stepsProfile' array
        updated_data=$(echo "$data" | jq --argjson step "$step_object" '.stepsProfile += [$step]')
    fi

    # Write to file
    echo "writing to file"
    echo "$updated_data" > profiling.json
}
