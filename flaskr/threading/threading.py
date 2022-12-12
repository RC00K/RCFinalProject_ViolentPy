import threading


def portthreading(ports, num_splits, scan, range_low, range_high):
    split_size = (range_high-range_low) // num_splits
    threads = []
    for i in range(num_splits):
        # Indices of the list thread handles
        start = i * split_size
        # Last chuck for uneven splits
        end = range_high if i+1 == num_splits else (i+1) * split_size
        # Thread created
        threads.append(
            threading.Thread(target=scan, args=(ports, start, end)))
        # Start the threading
        threads[-1].start()

    # Wait for thread to finish
    for t in threads:
        t.join()
