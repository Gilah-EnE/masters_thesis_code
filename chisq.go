/*
* Pearson chi-squared test module
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

func ChiSqTest(totalCounter map[byte]int, readBytesCount int) float64 {
	theoreticalDistribution := map[byte]float64{}
	for i := 0; i < 256; i++ {
		theoreticalDistribution[byte(i)] = float64(readBytesCount) / 256
	}

	var chiSquare, observed, expected float64
	for i := 0; i < 256; i++ {
		observed = float64(totalCounter[byte(i)])
		expected = theoreticalDistribution[byte(i)]
		chiSquare += math.Pow(observed-expected, 2) / expected
	}
	return chiSquare
}
