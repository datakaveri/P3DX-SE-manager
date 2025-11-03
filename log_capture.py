"""
Log capture module for enclave deployment box_out logs.
Captures only boxed messages from deployment stdout.
"""

import threading
import re
import subprocess
from typing import List


# In-memory storage for boxed log messages
box_logs: List[str] = []
box_logs_lock = threading.Lock()


def append_box_log(message: str) -> None:
    """Append a boxed log message to the in-memory list."""
    with box_logs_lock:
        box_logs.append(message)


def get_all_logs() -> List[str]:
    """Return all captured box log messages."""
    with box_logs_lock:
        return box_logs.copy()


def clear_logs() -> None:
    """Clear all captured logs (call when starting new deployment)."""
    with box_logs_lock:
        box_logs.clear()


def extract_box_message(box_text: str) -> str:
    """
    Extract just the message content from a boxed log.
    Input:  "+---+\n| Message |\n+---+"
    Output: "Message"
    """
    lines = box_text.splitlines()
    # Get content lines (skip top and bottom borders)
    content_lines = []
    for line in lines[1:-1]:  # Skip first and last line (borders)
        # Remove "| " prefix and " |" suffix
        if line.startswith("| ") and line.endswith(" |"):
            content_lines.append(line[2:-2].rstrip())
    return "\n".join(content_lines) if content_lines else "Unknown message"


def stream_and_capture_box_logs(proc: subprocess.Popen) -> None:
    """
    Stream subprocess stdout and capture box_out messages and application logs.
    Captures:
    - Boxed messages from box_out()
    - Round information (e.g., "Running round 0", "Round 5 completed")
    - Application completion messages
    Runs in background thread.
    """
    top_bottom_border_pattern = re.compile(r"^\+-+\+$")
    
    # Patterns to capture application logs (SERVER-SIDE SPECIFIC)
    round_patterns = [
        re.compile(r"Round:\s*(\d+)\s+Received Tasks", re.IGNORECASE),
        re.compile(r"Run\s+\d+\s+epoch\s+of\s+(\d+)\s+round", re.IGNORECASE),
        re.compile(r"Running round (\d+)", re.IGNORECASE),
        re.compile(r"Round (\d+)[:\s].*started", re.IGNORECASE),
        re.compile(r"Round (\d+)[:\s].*complete", re.IGNORECASE),
        re.compile(r"Sending tasks to collaborator.*round (\d+)", re.IGNORECASE),
        re.compile(r"Starting.*round (\d+)", re.IGNORECASE),
    ]
    
    important_patterns = [
        re.compile(r"✔️\s*OK", re.IGNORECASE),
        re.compile(r"exited with code 0", re.IGNORECASE),
        re.compile(r"Output saved to", re.IGNORECASE),
        re.compile(r"DONE", re.IGNORECASE),
        re.compile(r"Experiment [Cc]ompleted?", re.IGNORECASE),
        re.compile(r"Training complete", re.IGNORECASE),
        re.compile(r"Model saved", re.IGNORECASE),
        re.compile(r"Saving round \d+ model", re.IGNORECASE),
        re.compile(r"Results saved", re.IGNORECASE),
        re.compile(r"Aggregation complete", re.IGNORECASE),
        re.compile(r"Requesting tasks\.\.\.", re.IGNORECASE),
        re.compile(r"Starting Aggregator gRPC Server", re.IGNORECASE),
        re.compile(r"Insecure port:\s*\d+", re.IGNORECASE),
    ]
    
    in_box = False
    current_box_lines = []
    last_round_logged = -1  # Track last round to avoid duplicates
    recent_messages = set()  # Track recent messages to avoid duplicates
    
    try:
        for raw_line in iter(proc.stdout.readline, ""):
            if raw_line == "" and proc.poll() is not None:
                break
            line = raw_line.rstrip("\n")
            
            # Mirror to server stdout for debugging
            print(line, flush=True)

            if not in_box:
                if top_bottom_border_pattern.match(line):
                    in_box = True
                    current_box_lines = [line]
                else:
                    # Check for round information (only log once per round)
                    round_matched = False
                    for pattern in round_patterns:
                        match = pattern.search(line)
                        if match:
                            round_num = int(match.group(1))
                            if round_num != last_round_logged:
                                append_box_log(f"Running round {round_num}")
                                last_round_logged = round_num
                            round_matched = True
                            break
                    
                    # Check for important messages (only if not a round message)
                    if not round_matched:
                        for pattern in important_patterns:
                            if pattern.search(line):
                                # Extract the relevant part of the message
                                clean_line = line.strip()
                                # Remove common prefixes and log metadata
                                for prefix in ["INFO:", "DEBUG:", "[INFO]", "[DEBUG]", "server-1  |", "server-1 ", "[10/"]:
                                    if clean_line.startswith(prefix):
                                        clean_line = clean_line[len(prefix):].strip()
                                        break
                                # Remove timestamp patterns like "[10/06/25 06:04:02]"
                                clean_line = re.sub(r'^\[\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\]\s*', '', clean_line)
                                # Remove INFO/WARNING prefixes after timestamp
                                clean_line = re.sub(r'^(INFO|WARNING|DEBUG|ERROR)\s+', '', clean_line)
                                if clean_line and clean_line not in recent_messages:  # Only append if new
                                    append_box_log(clean_line)
                                    recent_messages.add(clean_line)
                                break
            else:
                current_box_lines.append(line)
                if top_bottom_border_pattern.match(line):
                    # Completed a box - extract message and store
                    box_text = "\n".join(current_box_lines)
                    message = extract_box_message(box_text)
                    if message not in recent_messages:
                        append_box_log(message)
                        recent_messages.add(message)
                    
                    in_box = False
                    current_box_lines = []
    except Exception:
        # Best-effort capture; don't crash the thread
        pass

