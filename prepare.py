"""
* File preparation utilities
* Copyright (C) 2025  Artem Stefankiv
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import os
import mmap
from typing import Tuple, List
from pygpt.gpt_file import GPTFile
from pygpt.partition_table_header import PartitionTableHeader


class GPTReader(object):
    def __init__(self, filename, sector_size=512, little_endian=True):
        self._filename = filename
        self._sector_size = sector_size
        self._file = GPTFile(filename, sector_size)
        self._pth = PartitionTableHeader(self._file, little_endian)

    @property
    def partition_table(self):
        return self._pth

    @property
    def block_reader(self):
        return self._file


def split_image(fname: str, sector_size=512, dry_run=False) -> list:
    reader = GPTReader(fname, sector_size=sector_size)
    files = list()

    if len(list(reader.partition_table.valid_entries())) == 0:
        raise ValueError("No valid partitions found")

    for partition in reader.partition_table.valid_entries():
        file_base_name = partition.partition_id

        out_file = os.path.join(os.getcwd(), f"{file_base_name}.bin")
        files.append(out_file)

        if not dry_run:
            with open(out_file, "wb+") as fout:
                for block in reader.block_reader.blocks_in_range(
                    partition.first_block, partition.length
                ):
                    fout.write(block)

    return files


def find_empty_regions(file_path: str, block_size: int = 512) -> List[Tuple[int, int]]:
    empty_regions = []
    region_start = None

    with open(file_path, "rb") as f:
        # Використовуємо mmap для ефективної роботи з великими файлами
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        file_size = len(mm)

        for pos in range(0, file_size, block_size):
            # Читаємо блок даних
            current_offset = min(pos + block_size, file_size)
            block = mm[pos:current_offset]
            if (current_offset / 1048576) % 1 == 0:
                print("Analyzing: ", current_offset / 1048576, end="\r")
            # Перевіряємо чи блок порожній (містить лише нулі)
            is_empty = all(b == 0 for b in block)

            if is_empty and region_start is None:
                region_start = pos
            elif not is_empty and region_start is not None:
                empty_regions.append((region_start, pos))
                region_start = None

        # Додаємо останній регіон, якщо він порожній
        if region_start is not None:
            empty_regions.append((region_start, file_size))
        print("")
        mm.close()

    return empty_regions


def optimize_disk_image(input_path: str, block_size: int = 512):
    # Знаходимо порожні регіони
    input_path_split = os.path.splitext(input_path)
    output_path = f"{input_path_split[0]}_opt{input_path_split[1]}"
    empty_regions = find_empty_regions(input_path, block_size)

    # Якщо порожніх регіонів немає, просто копіюємо файл
    if not empty_regions:
        if input_path != output_path:
            with open(input_path, "rb") as src, open(output_path, "wb") as dst:
                dst.write(src.read())
        return

    # Створюємо новий файл без порожніх регіонів
    with open(input_path, "rb") as src, open(output_path, "wb") as dst:
        current_pos = 0

        for start, end in empty_regions:
            # Копіюємо дані до порожнього регіону

            if current_pos < start:
                src.seek(current_pos)
                # Читаємо та записуємо файл блоками по 1 МБ
                bytes_to_copy = start - current_pos
                buffer_size = 512

                while bytes_to_copy > 0:
                    print(
                        f"Copying {bytes_to_copy} bytes from {start} to {end}                             ",
                        end="\r",
                    )
                    chunk_size = min(buffer_size, bytes_to_copy)
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dst.write(chunk)
                    bytes_to_copy -= len(chunk)

            # Пропускаємо порожній регіон
            current_pos = end

        # Копіюємо залишок даних після останнього порожнього регіону
        if current_pos < os.path.getsize(input_path):
            src.seek(current_pos)
            dst.write(src.read())

    print(f"{input_path.split("/")[-1]} -> {output_path.split("/")[-1]}: Done")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode")
    parser.add_argument("input_path")

    args = parser.parse_args()

    if args.mode == "optimize":
        optimize_disk_image(args.input_path, block_size=4096)
    elif args.mode == "split":
        split_image(args.input_path)
    elif args.mode == "both":
        splits = split_image(args.input_path)
        for split in splits:
            optimize_disk_image(split, block_size=512)
    else:
        raise ValueError("Invalid mode")


if __name__ == "__main__":
    main()
