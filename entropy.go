/*
* Entropy estimation test module
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

func EntropyEstimation(totalCounter map[byte]int, readBytesCount int) float64 {
	var p, entropy float64

	for i := 0; i < 256; i++ {
		p = float64(totalCounter[byte(i)]) / float64(readBytesCount)
		entropy += p * math.Log2(p)
	}
	return -entropy
}
