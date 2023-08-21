#!/bin/bash

function call_setstate_endpoint() {
  local endpoint="http://192.168.1.199:4000/enclave/setstate"
  local data=$(printf '{"state": {"description": "%s", "maxSteps": %d, "step": %d, "title": "%s"}}' "$1" "$2" "$3" "$4")  local data=$(printf '{"state": {"description": "%s", "maxSteps": %d, "step": %d, "title": "%s"}}' "$1" "$2" "$3" "$4")
  curl -X POST -H "Content-Type: application/json" -d "$data" "$endpoint"
}