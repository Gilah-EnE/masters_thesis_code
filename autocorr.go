/*
* Autocorrelation test module
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
	"log"
	"math"
	"os"

	"github.com/montanaflynn/stats"
)

func AutoCorrelation(filename string, blockSize int) float64 {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			log.Fatal(err)
		}
	}(file)

	buffer := make([]byte, blockSize)
	var totalAutocorr []float64

	var readBytesCount int
	for {
		bytesRead, err := file.Read(buffer)
		if bytesRead == 0 || err != nil {
			break
		}
		var results []float64
		readBytesCount += bytesRead
		fmt.Printf("%.1f \r", float32(readBytesCount)/1048576)

		if len(buffer) > bytesRead {
			break
		}

		var floatBuffer []float64

		inputMean := meanBytes(buffer)

		for _, val := range buffer {
			floatBuffer = append(floatBuffer, float64(val)-inputMean)
		}

		var maxLag int
		if len(floatBuffer) < 50 {
			maxLag = len(floatBuffer)
		} else {
			maxLag = 50
		}

		for lag := 1; lag < maxLag; lag++ {
			correlation, autocorrErr := stats.Correlation(floatBuffer[lag:], floatBuffer[:len(floatBuffer)-lag])
			if autocorrErr != nil {
				log.Println("Autocorrelation calc error: ", autocorrErr)
			}
			results = append(results, math.Abs(correlation))
		}

		totalAutocorr = append(totalAutocorr, meanFloats(results))
	}
	std, err := stats.StandardDeviation(totalAutocorr)
	if err != nil {
		log.Println("Standard deviation calc error: ", err)
		return 0.0
	}
	return std
}
