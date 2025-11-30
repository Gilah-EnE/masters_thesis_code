/*
* Compression test module
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
 */

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func performCompression(execCommand string) float64 {
	gzipOutput, err := exec.Command("bash", "-c", execCommand).CombinedOutput()
	if err != nil {
		fmt.Println(err)
	}

	gzipCompression, err := strconv.Atoi(strings.Split(string(gzipOutput), "\n")[0])
	if err != nil {
		fmt.Println(err)
	}
	return float64(gzipCompression)
}

func checkCompressionToolAvailability() error {
	tools := []string{"pigz", "lz4", "lbzip2", "zstd", "pixz"}
	for _, tool := range tools {
		_, err := exec.LookPath(tool)
		if err != nil {
			return fmt.Errorf("Інструмент %s не знайдено в PATH", tool)
		}
	}
	return nil
}

func CompressionTest(fileName string) float64 {

	var CompressionTestToolErr error = checkCompressionToolAvailability()
	if CompressionTestToolErr != nil {
		fmt.Println(CompressionTestToolErr)
		return 0.0
	}

	var gzipCompression, lz4Compression, bz2Compression, zstdCompression, xzCompression float64
	var gzipExec, lz4Exec, bz2Exec, zstdExec, xzExec string

	gzipExec = fmt.Sprintf("pigz < \"%s\" | wc -c", fileName)
	lz4Exec = fmt.Sprintf("lz4 < \"%s\" | wc -c", fileName)
	bz2Exec = fmt.Sprintf("lbzip2 < \"%s\" | wc -c", fileName)
	zstdExec = fmt.Sprintf("zstd < \"%s\" | wc -c", fileName)
	xzExec = fmt.Sprintf("pixz < \"%s\" | wc -c", fileName)

	stat, err := os.Stat(fileName)
	if err != nil {
		fmt.Println(err)
		return 0.0
	}

	fileSize := float64(stat.Size())

	gzipCompression = fileSize / performCompression(gzipExec)
	lz4Compression = fileSize / performCompression(lz4Exec)
	bz2Compression = fileSize / performCompression(bz2Exec)
	zstdCompression = fileSize / performCompression(zstdExec)
	xzCompression = fileSize / performCompression(xzExec)

	avgCompression := (gzipCompression + lz4Compression + bz2Compression + zstdCompression + xzCompression) / 5.0

	return avgCompression
}
