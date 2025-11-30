/*
* Kolmogorov test module
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
	"math"
)

func KsTest(totalCounter map[byte]int, readBytesCount int) (float64, int, int, float64, float64) {

	var empiricalCumSum float64
	var theoreticalCumSum float64
	var empiricalCDF []float64
	var theoreticalCDF []float64

	for i := 0; i < 256; i++ {
		empiricalCumSum += float64(totalCounter[byte(i)]) / float64(readBytesCount)
		theoreticalCumSum += float64(readBytesCount) / 256 / float64(readBytesCount)
		empiricalCDF = append(empiricalCDF, empiricalCumSum)
		theoreticalCDF = append(theoreticalCDF, theoreticalCumSum)
	}

	var ksDifferences []float64

	for idx := range empiricalCDF {
		ksDifferences = append(ksDifferences, math.Abs(empiricalCDF[idx]-theoreticalCDF[idx]))
	}
	ksStatistic := ksDifferences[0]
	maxDiffPosition := 0

	for idx, value := range ksDifferences {
		if value > ksStatistic {
			ksStatistic = value
			maxDiffPosition = idx
		} else {
			continue
		}
	}
	criticalValue001 := 1.63 / math.Sqrt(float64(readBytesCount))
	criticalValue005 := 1.36 / math.Sqrt(float64(readBytesCount))
	return ksStatistic, maxDiffPosition, readBytesCount, criticalValue001, criticalValue005
}
