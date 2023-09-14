#!/bin/bash

function profiling_func() {
    local stepno="$1"
    local description="$2"
    local timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

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
            "totalTime": 0
        }'
    fi

    # Check if a step with the same number exists in the "stepsProfile" array
    step_exists=$(echo "$data" | jq --arg stepno "$stepno" '.stepsProfile[] | has($stepno)')

    if [ "$step_exists" = "true" ]; then
        # Update the existing step with the same number
        updated_data=$(echo "$data" | jq --arg stepno "$stepno" --arg description "$description" --arg timestamp "$timestamp" '.stepsProfile[$stepno].description = $description | .stepsProfile[$stepno].timestamp = $timestamp')
    else
        # Construct the step object
        local step_object="{\"step$stepno\": {\"description\": \"$description\", \"timestamp\": \"$timestamp\"}}"
        
        # Add the step object to 'stepsProfile' array
        updated_data=$(echo "$data" | jq --argjson step "$step_object" '.stepsProfile += [$step]')
    fi

    # Write to file
    echo "$updated_data" > profiling.json
}
