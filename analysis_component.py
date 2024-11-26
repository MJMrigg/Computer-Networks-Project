import tqdm


def makeTQDM(file_size):
    progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=int(file_size))

    return progress
