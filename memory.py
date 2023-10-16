import psutil

def measure_memory_usage():
    process = psutil.Process()
    memory = process.memory_info().rss / (1024 * 1024)  # in MB
    return memory